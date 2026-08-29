from __future__ import annotations

from ravage.deterministic_agents.auth_forms import _forms_from_html
from ravage.probes.file_read.upload import (
    _file_input_name,
    _probe_uploaded_file_readback,
    _submit_multipart_upload,
    _upload_attempts,
    _upload_form_brief,
)
from ravage.runtime.common import clip
from ravage.web_core.http_probe import ProbeResponse, ProbeSession
from ravage.web_core.proof_recognizer import recognize_proofs

from .auth import (
    _auth_bypass_cases,
    _auth_bypass_finding,
    _credential_fields,
    _fork_probe_session,
    _login_bypass_succeeded,
    _login_replay_finding,
    _login_replay_succeeded,
    _login_targets,
    _response_bodies,
)
from .common import _dedupe, _string_items
from .context import ExtractorContext
from .models import _AuthBypassCase


class AuthFlowMixin(ExtractorContext):
    def _try_logins(self, credentials: list[tuple[str, str]]) -> list[dict[str, object]]:
        for username, password in credentials:
            if not username or not password or self.budget <= 0:
                continue
            finding = self._try_credential_pair(username, password)
            if finding is not None:
                return [finding]
        return []


    def _try_credential_pair(self, username: str, password: str) -> dict[str, object] | None:
        login_targets = _login_targets(self.state, self.session, include_fallback=True)
        for target in login_targets:
            if self.budget <= 0:
                break
            finding = self._try_login_replay(target, username=username, password=password)
            if finding is not None:
                return finding
        return None


    def _try_login_replay(
        self,
        target: dict[str, object],
        *,
        username: str,
        password: str,
    ) -> dict[str, object] | None:
        self.budget -= 1
        url = str(target.get("url") or "")
        fields = _credential_fields(target, username=username, password=password)
        response = self.session.post_form(url, fields)
        self._record_login_replay_response(response, url=url, username=username, password=password)

        if self.budget <= 0:
            return None

        self.budget -= 1
        home = self.session.get(self.session.target_url)
        self._record_login_replay_home(home)

        if not _login_replay_succeeded(response, home):
            return None
        return _login_replay_finding(
            url=url,
            username=username,
            password=password,
            fields=fields,
            response=response,
            home=home,
        )


    def _record_login_replay_response(
        self,
        response: ProbeResponse,
        *,
        url: str,
        username: str,
        password: str,
    ) -> None:
        self._record_response(
            response,
            target={"kind": "login_replay", "url": url, "input": "password"},
            phase="login_replay",
            payload=f"{username}:{password}",
            expr="credential replay",
        )


    def _record_login_replay_home(self, response: ProbeResponse) -> None:
        self._record_response(
            response,
            target={"kind": "login_replay", "url": self.session.target_url, "input": "session"},
            phase="login_replay",
            payload="post-login home",
            expr="credential replay",
        )


    def _try_sqli_auth_bypass(
        self,
        usernames: list[str],
        *,
        include_fallback: bool = False,
        max_requests: int | None = None,
        reserve_budget: int = 0,
    ) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        candidate_users = _dedupe([*usernames, "admin", "administrator", "root"])[:4]
        start_budget = self.budget
        for target in _login_targets(self.state, self.session, include_fallback=include_fallback):
            if self._auth_bypass_budget_exhausted(start_budget, max_requests=max_requests, reserve_budget=reserve_budget):
                break
            finding = self._try_sqli_auth_bypass_target(
                target,
                candidate_users=candidate_users,
                start_budget=start_budget,
                max_requests=max_requests,
                reserve_budget=reserve_budget,
            )
            if finding is not None:
                findings.append(finding)
                return findings
            if self._auth_bypass_budget_exhausted(start_budget, max_requests=max_requests, reserve_budget=reserve_budget):
                return findings
        return findings


    def _try_sqli_auth_bypass_target(
        self,
        target: dict[str, object],
        *,
        candidate_users: list[str],
        start_budget: int,
        max_requests: int | None,
        reserve_budget: int,
    ) -> dict[str, object] | None:
        url = str(target.get("url") or "")
        if not url:
            return None

        for case in _auth_bypass_cases(candidate_users):
            if self._auth_bypass_budget_exhausted(start_budget, max_requests=max_requests, reserve_budget=reserve_budget):
                return None
            finding = self._try_sqli_auth_bypass_case(target, url=url, case=case)
            if finding is not None:
                return finding
        return None


    def _try_sqli_auth_bypass_case(
        self,
        target: dict[str, object],
        *,
        url: str,
        case: _AuthBypassCase,
    ) -> dict[str, object] | None:
        session = _fork_probe_session(self.session)
        fields = _credential_fields(target, username=case.username, password=case.password)
        self.budget -= 1
        response = session.post_form(url, fields)
        self._record_auth_bypass_response(response, url=url, case=case)

        if not _login_bypass_succeeded(response):
            return None
        return self._handle_successful_auth_bypass(session, url=url, case=case, response=response)


    def _record_auth_bypass_response(
        self,
        response: ProbeResponse,
        *,
        url: str,
        case: _AuthBypassCase,
    ) -> None:
        self._record_response(
            response,
            target={"kind": "login_sqli_bypass", "url": url, "input": case.input_name},
            phase="login_sqli_bypass",
            payload=clip(case.payload, 120),
            expr=case.expr,
        )


    def _handle_successful_auth_bypass(
        self,
        session: ProbeSession,
        *,
        url: str,
        case: _AuthBypassCase,
        response: ProbeResponse,
    ) -> dict[str, object]:
        followups, forms = self._sqli_auth_followup(session, response)
        finding = _auth_bypass_finding(
            url=url,
            case=case,
            response=response,
            followups=followups,
            forms=forms,
        )
        self.findings.append(finding)
        if self._register_auth_bypass_proofs(url=url, case=case, response=response, followups=followups):
            return finding

        upload_findings = self._try_authenticated_uploads(session, forms)
        if upload_findings:
            finding["upload_findings"] = upload_findings
        return finding


    def _register_auth_bypass_proofs(
        self,
        *,
        url: str,
        case: _AuthBypassCase,
        response: ProbeResponse,
        followups: list[ProbeResponse],
    ) -> bool:
        proof_target: dict[str, object] = {"kind": "login_sqli_bypass", "url": url, "input": case.input_name}
        for body in _response_bodies(response, followups):
            self._register_blind_proof(body, proof_target, "login_sqli_bypass")
            if self.proofs:
                return True
        return False


    def _auth_bypass_budget_exhausted(
        self,
        start_budget: int,
        *,
        max_requests: int | None,
        reserve_budget: int,
    ) -> bool:
        if self.budget <= reserve_budget:
            return True
        if max_requests is not None and start_budget - self.budget >= max_requests:
            return True
        return False


    def _sqli_auth_followup(
        self,
        session: ProbeSession,
        response: ProbeResponse,
    ) -> tuple[list[ProbeResponse], list[dict[str, object]]]:
        urls = _dedupe(
            [
                str(response.headers.get("location") or response.headers.get("Location") or ""),
                "/dashboard.php",
                "/dashboard",
                "/upload.php",
                "/upload",
                "/account",
                "/profile",
                "/",
            ]
        )
        followups: list[ProbeResponse] = []
        forms: list[dict[str, object]] = []
        for url in urls[:8]:
            if not url or self.budget <= 0:
                continue
            self.budget -= 1
            page = session.get(url)
            followups.append(page)
            self._record_response(
                page,
                target={"kind": "login_sqli_bypass", "url": session.absolute(url), "input": "session"},
                phase="login_sqli_followup",
                payload=url,
                expr="authenticated follow-up",
            )
            forms.extend(_forms_from_html(page.final_url, page.body, auth_headers={}, base_categories=("authenticated",)))
        return followups, forms


    def _try_authenticated_uploads(
        self,
        session: ProbeSession,
        forms: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        for form in forms[:6]:
            file_field = _file_input_name(form)
            if not file_field:
                continue
            for upload in _upload_attempts(form=form):
                if self.budget <= 0:
                    return findings
                self.budget -= 1
                response = _submit_multipart_upload(session, form, file_field=file_field, upload=upload)
                self._record_response(
                    response,
                    target={"kind": "authenticated_upload", "url": str(form.get("action") or ""), "input": file_field},
                    phase="login_sqli_upload",
                    payload=str(upload["filename"]),
                    expr="authenticated upload",
                )
                proofs = recognize_proofs(response.body)
                if proofs:
                    self.proofs.extend(proof for proof in proofs if proof not in self.proofs)
                    finding = {
                        "type": "file_upload_extracted_proof",
                        "form": _upload_form_brief(form),
                        "file_field": file_field,
                        "filename": upload["filename"],
                        "proofs": proofs,
                        "response": response.summary(body_chars=700),
                    }
                    findings.append(finding)
                    self.findings.append(finding)
                    return findings
                readback, requests, remaining = _probe_uploaded_file_readback(
                    session,
                    form=form,
                    upload=upload,
                    upload_response=response,
                    budget=min(self.budget, 12),
                )
                consumed = min(self.budget, 12) - remaining
                self.budget -= max(0, consumed)
                for request in requests:
                    self.requests.append(request | {"phase": "login_sqli_upload_readback"})
                if readback:
                    findings.append(readback)
                    proofs = _string_items(readback.get("proofs"))
                    if proofs:
                        self.findings.append(readback)
                    for proof in proofs:
                        if proof not in self.proofs:
                            self.proofs.append(proof)
                    if proofs:
                        return findings
        return findings

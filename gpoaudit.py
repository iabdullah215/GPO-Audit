from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional
from xml.etree import ElementTree as ET

from bs4 import BeautifulSoup
from colorama import init, Fore, Style

                     
init(autoreset=True)


@dataclass(frozen=True)
class SecurityCheck:
    name: str
    pattern: re.Pattern[str]
    level: str
    message: str


@dataclass(frozen=True)
class Finding:
    level: str
    category: str
    title: str
    message: str
    context: Optional[str] = None
    source: Optional[str] = None
    gpo_name: Optional[str] = None
    input_file: Optional[str] = None

    def fingerprint(self) -> str:
                                                                              
        payload = "|".join([
            self.level,
            self.category,
            self.title,
            self.message,
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class GPOMetadata:
    name: Optional[str] = None
    guid: Optional[str] = None
    domain: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    owner: Optional[str] = None
    wmi_filter: Optional[str] = None
    security_filtering: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    link_details: list[dict[str, str]] = field(default_factory=list)


@dataclass
class AuditReport:
    source: str
    input_file: str
    gpo_name: str
    metadata: GPOMetadata
    findings: list[Finding] = field(default_factory=list)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _xml_findtext_by_localname(root: ET.Element, localname: str) -> Optional[str]:
    for elem in root.iter():
        if _local_name(elem.tag).lower() == localname.lower() and elem.text:
            txt = " ".join(elem.text.split())
            if txt:
                return txt
    return None


def _xml_findall_by_localname(root: ET.Element, localname: str) -> list[ET.Element]:
    matches: list[ET.Element] = []
    for elem in root.iter():
        if _local_name(elem.tag).lower() == localname.lower():
            matches.append(elem)
    return matches


def _safe_str(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    s = " ".join(v.split())
    return s or None

class GPOAuditor:
    def __init__(self):
        self.gpo_name = "Unknown"
        self.sid_pattern = re.compile(r"S-1-5-[0-9-]+")
        self.reports: list[AuditReport] = []
        self._active_report: Optional[AuditReport] = None
        self.security_checks: tuple[SecurityCheck, ...] = (
            SecurityCheck(
                name="Firewall",
                pattern=re.compile(r"Firewall state.*(Disabled|Off)", re.IGNORECASE),
                level="CRITICAL",
                message="Windows Firewall is DISABLED.",
            ),
            SecurityCheck(
                name="WSUS HTTP",
                pattern=re.compile(r"http://.*:8530", re.IGNORECASE),
                level="CRITICAL",
                message="WSUS is using insecure HTTP (WSUSpect risk).",
            ),
            SecurityCheck(
                name="SMB Signing",
                pattern=re.compile(r"Digitally sign communications.*Disabled", re.IGNORECASE),
                level="HIGH",
                message="SMB Signing is DISABLED (Relay risk).",
            ),
            SecurityCheck(
                name="PS Logging",
                pattern=re.compile(r"PowerShell Script Block Logging.*Disabled", re.IGNORECASE),
                level="HIGH",
                message="PowerShell Audit Logging is DISABLED.",
            ),
            SecurityCheck(
                name="Anonymous SAM",
                pattern=re.compile(
                    r"Network access: Do not allow anonymous enumeration.*Disabled",
                    re.IGNORECASE,
                ),
                level="HIGH",
                message="Anonymous SAM enumeration allowed.",
            ),
            SecurityCheck(
                name="LAPS",
                pattern=re.compile(r"LAPS.*Disabled", re.IGNORECASE),
                level="HIGH",
                message="LAPS (Local Admin Passwords) appears DISABLED.",
            ),
            SecurityCheck(
                name="SSL/TLS",
                pattern=re.compile(r"Use (SSL 3\.0|TLS 1\.0).*Enabled", re.IGNORECASE),
                level="CRITICAL",
                message="Legacy/Crackable Encryption protocols enabled.",
            ),

                                             
            SecurityCheck(
                name="NTLMv1 allowed",
                pattern=re.compile(
                    r"LAN Manager authentication level.*(Send LM|LM\s*&\s*NTLM|NTLMv1|Send NTLM response only)",
                    re.IGNORECASE,
                ),
                level="HIGH",
                message="NTLMv1/LM responses appear allowed (weaker auth; relay/downgrade risk).",
            ),
            SecurityCheck(
                name="Store LM hashes",
                pattern=re.compile(
                    r"Do not store LAN Manager hash value.*(Disabled|Off)",
                    re.IGNORECASE,
                ),
                level="HIGH",
                message="LM hash storage appears allowed (should be Enabled/On to prevent LM hashes).",
            ),
            SecurityCheck(
                name="LDAP server signing not required",
                pattern=re.compile(
                    r"LDAP server signing requirements.*(None|Not required|Disabled|Off)",
                    re.IGNORECASE,
                ),
                level="HIGH",
                message="LDAP server signing is not required (MITM/credential exposure risk).",
            ),
            SecurityCheck(
                name="LDAP client signing not required",
                pattern=re.compile(
                    r"LDAP client signing requirements.*(None|Not required|Disabled|Off)",
                    re.IGNORECASE,
                ),
                level="MED",
                message="LDAP client signing is not required (weaker LDAP security).",
            ),
            SecurityCheck(
                name="LDAP channel binding weak",
                pattern=re.compile(
                    r"LDAP server channel binding token requirements.*(Never|When supported|Disabled|Off)",
                    re.IGNORECASE,
                ),
                level="MED",
                message="LDAP channel binding appears not enforced (review for LDAPS/CBT hardening).",
            ),
            SecurityCheck(
                name="Insecure guest logons",
                pattern=re.compile(
                    r"(Enable insecure guest logons|Insecure guest logons).*Enabled",
                    re.IGNORECASE,
                ),
                level="HIGH",
                message="Insecure SMB guest logons appear enabled (unauthenticated access risk).",
            ),
            SecurityCheck(
                name="Anonymous Everyone permissions",
                pattern=re.compile(
                    r"Let Everyone permissions apply to anonymous users.*Enabled",
                    re.IGNORECASE,
                ),
                level="HIGH",
                message="Everyone permissions apply to anonymous users (anonymous access risk).",
            ),
            SecurityCheck(
                name="Anonymous named pipes/shares",
                pattern=re.compile(
                    r"Restrict anonymous access to Named Pipes and Shares.*Disabled",
                    re.IGNORECASE,
                ),
                level="HIGH",
                message="Anonymous access to named pipes/shares may be allowed (anonymous access risk).",
            ),

                                           
            SecurityCheck(
                name="Kerberos weak encryption",
                pattern=re.compile(
                    r"(encryption types allowed for Kerberos|Kerberos encryption types).*(DES|DES_CBC|RC4)"
                    r"|\bDES\b",
                    re.IGNORECASE,
                ),
                level="MED",
                message="Weak Kerberos encryption types may be enabled (review DES/RC4 exposure).",
            ),

                                                                     
            SecurityCheck(
                name="Defender real-time protection off",
                pattern=re.compile(
                    r"Turn off real-time protection.*Enabled",
                    re.IGNORECASE,
                ),
                level="CRITICAL",
                message="Microsoft Defender real-time protection appears turned OFF.",
            ),
            SecurityCheck(
                name="Defender tamper protection off",
                pattern=re.compile(
                    r"Tamper Protection.*(Disabled|Off)",
                    re.IGNORECASE,
                ),
                level="HIGH",
                message="Defender Tamper Protection appears disabled.",
            ),
            SecurityCheck(
                name="ASR rules disabled",
                pattern=re.compile(
                    r"(Attack Surface Reduction|ASR).*(Disabled|Not configured)",
                    re.IGNORECASE,
                ),
                level="MED",
                message="Attack Surface Reduction (ASR) appears disabled or not configured.",
            ),

                                    
            SecurityCheck(
                name="WDigest UseLogonCredential",
                pattern=re.compile(
                    r"UseLogonCredential.*(1|Enabled|True)"
                    r"|WDigest.*(Enabled|On)",
                    re.IGNORECASE,
                ),
                level="CRITICAL",
                message="WDigest UseLogonCredential appears enabled (cleartext credential caching risk).",
            ),
            SecurityCheck(
                name="LSA protection off (RunAsPPL)",
                pattern=re.compile(
                    r"(RunAsPPL|LSA protection|LSASS as a protected process).*(0|Disabled|Off)",
                    re.IGNORECASE,
                ),
                level="HIGH",
                message="LSA protection (RunAsPPL) appears disabled (credential theft hardening missing).",
            ),
            SecurityCheck(
                name="Credential Guard off",
                pattern=re.compile(
                    r"Credential Guard.*(Disabled|Off|Not enabled)"
                    r"|Turn on Virtualization Based Security.*(Disabled|Off)",
                    re.IGNORECASE,
                ),
                level="MED",
                message="Credential Guard/VBS appears disabled (if applicable, consider enabling).",
            ),
        )

    def _parse_duration_to_minutes(self, value: int, unit: str) -> Optional[int]:
        u = unit.strip().lower()
        if u.startswith('min'):
            return value
        if u.startswith('hour') or u == 'h':
            return value * 60
        if u.startswith('day') or u == 'd':
            return value * 24 * 60
        return None

    def _audit_kerberos_ticket_lifetimes(self, content: str) -> int:
                                                                            
                                             
                                                  
                                       
                           
                                 
        baselines_minutes = {
            "service_ticket": 600,
            "user_ticket": 10 * 60,
            "renewal": 7 * 24 * 60,
            "clock_skew": 5,
        }

        patterns = {
            "service_ticket": re.compile(
                r"Maximum lifetime for service ticket\s*:?\s*(\d+)\s*(minutes|minute|hours|hour|days|day)",
                re.IGNORECASE,
            ),
            "user_ticket": re.compile(
                r"Maximum lifetime for user ticket\s*:?\s*(\d+)\s*(minutes|minute|hours|hour|days|day)",
                re.IGNORECASE,
            ),
            "renewal": re.compile(
                r"Maximum lifetime for user ticket renewal\s*:?\s*(\d+)\s*(minutes|minute|hours|hour|days|day)",
                re.IGNORECASE,
            ),
            "clock_skew": re.compile(
                r"Maximum tolerance for computer clock synchronization\s*:?\s*(\d+)\s*(minutes|minute|hours|hour)",
                re.IGNORECASE,
            ),
        }

        label = {
            "service_ticket": "Maximum lifetime for service ticket",
            "user_ticket": "Maximum lifetime for user ticket",
            "renewal": "Maximum lifetime for user ticket renewal",
            "clock_skew": "Maximum tolerance for computer clock synchronization",
        }

        issues = 0
        for key, pat in patterns.items():
            m = pat.search(content)
            if not m:
                continue
            value = int(m.group(1))
            unit = m.group(2)
            minutes = self._parse_duration_to_minutes(value, unit)
            if minutes is None:
                continue

            baseline = baselines_minutes[key]
            if minutes <= baseline:
                continue

                                                                             
            level = "MED" if minutes <= baseline * 2 else "HIGH"
            msg = f"{label[key]} is {value} {unit} (baseline {baseline} minutes)."
            color = Fore.YELLOW if level in {"MED", "HIGH"} else Fore.GREEN
            print(f"{color}[{level}] Kerberos policy: {msg}")
            self._add_finding(
                self._mk_finding(
                    level=level,
                    category="Kerberos",
                    title=label[key],
                    message=msg,
                )
            )
            issues += 1

        return issues

    def _start_report(self, *, source: str, input_file: Path, gpo_name: str, metadata: GPOMetadata) -> None:
        report = AuditReport(
            source=source,
            input_file=str(input_file),
            gpo_name=gpo_name,
            metadata=metadata,
        )
        self.reports.append(report)
        self._active_report = report

    def _add_finding(self, finding: Finding) -> None:
        if self._active_report is None:
            return
        fp = finding.fingerprint()
        for existing in self._active_report.findings:
            if existing.fingerprint() == fp:
                return
        self._active_report.findings.append(finding)

    def _mk_finding(self, *, level: str, category: str, title: str, message: str, context: Optional[str] = None) -> Finding:
        source = self._active_report.source if self._active_report else None
        gpo_name = self._active_report.gpo_name if self._active_report else self.gpo_name
        input_file = self._active_report.input_file if self._active_report else None
        return Finding(
            level=level,
            category=category,
            title=title,
            message=message,
            context=_safe_str(context),
            source=source,
            gpo_name=gpo_name,
            input_file=input_file,
        )

    def _read_text_file(self, file_path: Path, encodings: Iterable[str]) -> str:
        encodings_list = list(encodings)
        if not encodings_list:
            raise ValueError("encodings must not be empty")

        last_error: Optional[Exception] = None
        for encoding in encodings_list:
            try:
                return file_path.read_text(encoding=encoding, errors="strict")
            except UnicodeError as exc:
                last_error = exc
                                                                                 
        return file_path.read_text(encoding=encodings_list[0], errors="ignore")

    def _collect_sids(self, content: str) -> list[str]:
        return sorted(set(self.sid_pattern.findall(content)))

    def _collect_resolved_sids_from_xml(self, root: ET.Element) -> set[str]:
                                                                                    
        resolved: set[str] = set()

        def record_if_resolved(container: ET.Element) -> None:
            sid = None
            name = None
            for child in list(container):
                lname = _local_name(child.tag).lower()
                if lname == 'sid':
                    sid = _safe_str(child.text)
                elif lname == 'name':
                    name = _safe_str(child.text)
            if sid and name and not self.sid_pattern.fullmatch(name):
                resolved.add(sid)

                                                     
        for elem in root.iter():
            lname = _local_name(elem.tag).lower()
            if lname in {'member', 'trustee', 'owner', 'group'}:
                record_if_resolved(elem)

        return resolved

    def _is_likely_resolved_in_text(self, contexts: list[str]) -> bool:
                                                                                                   
        name_like_showing = re.compile(r"[A-Za-z0-9_.-]+\\[^|]{2,}")
        keywords = (
            "nt authority\\",
            "builtin\\",
            "domain admins",
            "enterprise admins",
            "authenticated users",
            "system",
        )
        for ctx in contexts:
            c = ctx.lower()
            if name_like_showing.search(ctx):
                return True
            if any(k in c for k in keywords):
                return True
        return False

    def _is_admin_delegation_context(self, contexts: list[str]) -> bool:
                                                                                     
        keywords = (
            "edit, delete, modify security",
            "edit settings, delete, modify security",
            "edit settings",
            "modify security",
            "full control",
        )
        for ctx in contexts:
            c = ctx.lower()
            if any(k in c for k in keywords):
                return True
        return False

    def _extract_sid_contexts_from_text(self, text: str, sid: str, max_contexts: int = 3) -> list[str]:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        contexts: list[str] = []
        for idx, line in enumerate(lines):
            if sid not in line:
                continue

                                                                                        
            window = lines[max(0, idx - 2) : min(len(lines), idx + 3)]
            context = " | ".join(window)
            if context not in contexts:
                contexts.append(context)
            if len(contexts) >= max_contexts:
                break

        return contexts

    def _extract_sid_contexts_from_html(self, soup: BeautifulSoup, sid: str) -> list[str]:
                                                                                   
        text = soup.get_text("\n", strip=True)
        return self._extract_sid_contexts_from_text(text, sid)

    def _extract_sid_contexts_from_xml(self, root: ET.Element, sid: str, max_contexts: int = 3) -> list[str]:
        contexts: list[str] = []

        def walk(elem: ET.Element, path: list[str]) -> None:
            nonlocal contexts
            if len(contexts) >= max_contexts:
                return

            current_path = path + [elem.tag]
                                
            if elem.text and sid in elem.text:
                snippet = " ".join(elem.text.split())
                contexts.append(f"{'/'.join(current_path)}: {snippet}")
                if len(contexts) >= max_contexts:
                    return

                              
            for k, v in elem.attrib.items():
                if sid in v:
                    contexts.append(f"{'/'.join(current_path)}[@{k}={v}]")
                    if len(contexts) >= max_contexts:
                        return

            for child in list(elem):
                walk(child, current_path)

        walk(root, [])
        return contexts

    def _extract_sid_contexts_from_xml_structured(self, root: ET.Element) -> dict[str, list[str]]:
                                                                        
        contexts: dict[str, list[str]] = {}

        def add(s: str, ctx: str) -> None:
            if not s:
                return
            contexts.setdefault(s, [])
            if ctx not in contexts[s]:
                contexts[s].append(ctx)

                                                                                                            
        for ura in _xml_findall_by_localname(root, 'UserRightsAssignment'):
            right_name: Optional[str] = None
            for child in list(ura):
                if _local_name(child.tag).lower() == 'name':
                    right_name = _safe_str(child.text)
                    break
            if not right_name:
                continue

            for member in list(ura):
                if _local_name(member.tag).lower() != 'member':
                    continue
                member_sid = None
                member_name = None
                for mchild in list(member):
                    lname = _local_name(mchild.tag).lower()
                    if lname == 'sid':
                        member_sid = _safe_str(mchild.text)
                    elif lname == 'name':
                        member_name = _safe_str(mchild.text)
                if member_sid:
                    label = member_name or '(no name)'
                    add(member_sid, f"UserRightsAssignment {right_name}: {label} ({member_sid})")

                                                                                     
        for tp in _xml_findall_by_localname(root, 'TrusteePermissions'):
            trustee_name = None
            trustee_sid = None
            access = None

            trustee = None
            for child in list(tp):
                if _local_name(child.tag).lower() == 'trustee':
                    trustee = child
                    break

            if trustee is not None:
                for tchild in list(trustee):
                    lname = _local_name(tchild.tag).lower()
                    if lname == 'sid':
                        trustee_sid = _safe_str(tchild.text)
                    elif lname == 'name':
                        trustee_name = _safe_str(tchild.text)

            for child in tp.iter():
                if _local_name(child.tag).lower() == 'gpogroupedaccessenum':
                    access = _safe_str(child.text)
                    break

            if trustee_sid and (trustee_name or access):
                add(trustee_sid, f"Delegation {trustee_name or trustee_sid}: {access or '(unknown permission)'}")

                                                                                                          
        for so in _xml_findall_by_localname(root, 'SecurityOptions'):
            key_name = None
            display_name = None
            setting_value = None

            for child in list(so):
                lname = _local_name(child.tag).lower()
                if lname == 'keyname':
                    key_name = _safe_str(child.text)
                elif lname.startswith('setting'):
                    setting_value = _safe_str(child.text)
                elif lname == 'display':
                    for dchild in list(child):
                        if _local_name(dchild.tag).lower() == 'name':
                            display_name = _safe_str(dchild.text)
                            break

            text_blob = " ".join([v for v in [key_name, display_name, setting_value] if v])
            if not text_blob:
                continue
            for sid in self._collect_sids(text_blob):
                add(sid, f"SecurityOption {display_name or key_name}: {setting_value or ''}".strip())

        return contexts

    def _extract_security_options_from_xml(self, root: ET.Element) -> dict[str, str]:
                                                      
        opts: dict[str, str] = {}
        for so in _xml_findall_by_localname(root, 'SecurityOptions'):
            key_name = None
            value = None
            for child in list(so):
                lname = _local_name(child.tag).lower()
                if lname == 'keyname':
                    key_name = _safe_str(child.text)
                elif lname in {'settingnumber', 'settingstring', 'settingboolean'}:
                    value = _safe_str(child.text)
            if key_name and value is not None:
                opts[key_name] = value
        return opts

    def _extract_security_options_display_map_from_xml(self, root: ET.Element) -> dict[str, str]:
                                                         
        display_map: dict[str, str] = {}
        for so in _xml_findall_by_localname(root, 'SecurityOptions'):
            display_name = None
            display_value = None
            for child in list(so):
                if _local_name(child.tag).lower() != 'display':
                    continue
                for dchild in list(child):
                    lname = _local_name(dchild.tag).lower()
                    if lname == 'name':
                        display_name = _safe_str(dchild.text)
                    elif lname in {'displaystring', 'value', 'setting'}:
                        display_value = _safe_str(dchild.text)
            if display_name and display_value:
                display_map[display_name] = display_value
        return display_map

    def _xml_display_text(self, root: ET.Element) -> str:
                                                                                 
                                                                  
        lines: list[str] = []
        for disp in _xml_findall_by_localname(root, 'Display'):
            name = None
            val = None
            for child in list(disp):
                lname = _local_name(child.tag).lower()
                if lname == 'name':
                    name = _safe_str(child.text)
                elif lname == 'displaystring':
                    val = _safe_str(child.text)
            if name and val:
                lines.append(f"{name}: {val}")
        return "\n".join(lines)

    def _audit_security_options_xml(self, root: ET.Element) -> int:
                                                                                                 
        opts = self._extract_security_options_from_xml(root)
        display_map = self._extract_security_options_display_map_from_xml(root)
        if not opts:
                                                            
            opts = {}

        issues = 0

        def get_int(key: str) -> Optional[int]:
            if key not in opts:
                return None
            raw = opts[key].strip().strip('"')
            try:
                return int(raw)
            except ValueError:
                return None

                              
        lm_compat = get_int(r"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel")
        if lm_compat is not None and lm_compat < 5:
            msg = f"LmCompatibilityLevel is {lm_compat} (recommend 5: NTLMv2 only; refuse LM/NTLM)."
            print(f"{Fore.YELLOW}[HIGH] {msg}")
            self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="NTLM hardening", message=msg))
            issues += 1

                                                   
        lm_label = None
        for k in display_map.keys():
            if k.lower().startswith('network security: lan manager authentication level'):
                lm_label = k
                break
        if lm_label:
            v = display_map[lm_label].lower()
            if 'lm' in v or 'ntlmv1' in v or 'ntlm v1' in v:
                msg = f"{lm_label} is set to '{display_map[lm_label]}' (allows LM/NTLMv1; recommend NTLMv2 only)."
                print(f"{Fore.YELLOW}[HIGH] {msg}")
                self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="LAN Manager auth level", message=msg))
                issues += 1

                                                                      
        restrict_recv = get_int(r"MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic")
        if restrict_recv is not None and restrict_recv == 0:
            msg = "RestrictReceivingNTLMTraffic is 0 (incoming NTLM not restricted)."
            print(f"{Fore.YELLOW}[MED] {msg}")
            self._add_finding(self._mk_finding(level="MED", category="Hardening", title="Restrict NTLM (incoming)", message=msg))
            issues += 1

        restrict_send = get_int(r"MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic")
        if restrict_send is not None and restrict_send == 0:
            msg = "RestrictSendingNTLMTraffic is 0 (outgoing NTLM not restricted)."
            print(f"{Fore.YELLOW}[MED] {msg}")
            self._add_finding(self._mk_finding(level="MED", category="Hardening", title="Restrict NTLM (outgoing)", message=msg))
            issues += 1

        for label in display_map.keys():
            l = label.lower()
            if not l.startswith('network security: restrict ntlm:'):
                continue
            val = display_map[label]
            if val.lower() in {'disabled', 'not defined', 'not configured', 'none'}:
                msg = f"{label} is '{val}' (NTLM not restricted)."
                print(f"{Fore.YELLOW}[MED] {msg}")
                self._add_finding(self._mk_finding(level="MED", category="Hardening", title="Restrict NTLM", message=msg))
                issues += 1

        no_lm_hash = get_int(r"MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash")
        if no_lm_hash is not None and no_lm_hash == 0:
            msg = "NoLMHash is 0 (LM hashes may be stored; should be 1)."
            print(f"{Fore.YELLOW}[HIGH] {msg}")
            self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="LM hash storage", message=msg))
            issues += 1

        everyone_includes_anon = get_int(r"MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous")
        if everyone_includes_anon is not None and everyone_includes_anon == 1:
            msg = "EveryoneIncludesAnonymous is 1 (Everyone perms apply to anonymous users; should be 0)."
            print(f"{Fore.YELLOW}[HIGH] {msg}")
            self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="Anonymous access", message=msg))
            issues += 1

        allow_insecure_guest = get_int(r"MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\AllowInsecureGuestAuth")
        if allow_insecure_guest is not None and allow_insecure_guest == 1:
            msg = "AllowInsecureGuestAuth is 1 (insecure SMB guest logons enabled; should be 0)."
            print(f"{Fore.YELLOW}[HIGH] {msg}")
            self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="SMB guest", message=msg))
            issues += 1

                                        
        ldap_client_integrity = get_int(r"MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity")
        if ldap_client_integrity is not None and ldap_client_integrity < 2:
            msg = f"LDAPClientIntegrity is {ldap_client_integrity} (recommend 2: require signing)."
            print(f"{Fore.YELLOW}[MED] {msg}")
            self._add_finding(self._mk_finding(level="MED", category="Hardening", title="LDAP client signing", message=msg))
            issues += 1

        ldap_server_integrity = get_int(r"MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity")
        if ldap_server_integrity is not None and ldap_server_integrity < 2:
            msg = f"LDAPServerIntegrity is {ldap_server_integrity} (recommend 2: require signing)."
            print(f"{Fore.YELLOW}[HIGH] {msg}")
            self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="LDAP server signing", message=msg))
            issues += 1

        ldap_cbt = get_int(r"MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding")
        if ldap_cbt is not None and ldap_cbt < 2:
            msg = f"LdapEnforceChannelBinding is {ldap_cbt} (recommend 2: always enforce)."
            print(f"{Fore.YELLOW}[MED] {msg}")
            self._add_finding(self._mk_finding(level="MED", category="Hardening", title="LDAP channel binding", message=msg))
            issues += 1

                                                                          
        for label, val in display_map.items():
            ll = label.lower()
            vv = val.lower()
            if ll.startswith('domain controller: ldap server signing requirements'):
                if 'none' in vv or 'not required' in vv or 'disabled' in vv:
                    msg = f"{label} is '{val}' (should require signing)."
                    print(f"{Fore.YELLOW}[HIGH] {msg}")
                    self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="LDAP server signing", message=msg))
                    issues += 1
            if ll.startswith('network security: ldap client signing requirements'):
                if 'none' in vv or 'not required' in vv or 'disabled' in vv:
                    msg = f"{label} is '{val}' (should require signing)."
                    print(f"{Fore.YELLOW}[MED] {msg}")
                    self._add_finding(self._mk_finding(level="MED", category="Hardening", title="LDAP client signing", message=msg))
                    issues += 1
            if ll.startswith('domain controller: ldap server channel binding token requirements'):
                if 'never' in vv or 'when supported' in vv or 'disabled' in vv:
                    msg = f"{label} is '{val}' (recommend always, if compatible)."
                    print(f"{Fore.YELLOW}[MED] {msg}")
                    self._add_finding(self._mk_finding(level="MED", category="Hardening", title="LDAP channel binding", message=msg))
                    issues += 1

                                
        use_logon_cred = get_int(r"MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential")
        if use_logon_cred is not None and use_logon_cred == 1:
            msg = "WDigest UseLogonCredential is 1 (cleartext creds may be stored; should be 0)."
            print(f"{Fore.RED}[CRITICAL] {msg}")
            self._add_finding(self._mk_finding(level="CRITICAL", category="Hardening", title="WDigest", message=msg))
            issues += 1

        run_as_ppl = get_int(r"MACHINE\System\CurrentControlSet\Control\Lsa\RunAsPPL")
        if run_as_ppl is not None and run_as_ppl == 0:
            msg = "RunAsPPL is 0 (LSA protection off; consider enabling)."
            print(f"{Fore.YELLOW}[HIGH] {msg}")
            self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="LSA protection", message=msg))
            issues += 1

                               
        disable_rt = get_int(r"MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring")
        if disable_rt is not None and disable_rt == 1:
            msg = "Defender policy disables real-time monitoring (DisableRealtimeMonitoring=1)."
            print(f"{Fore.RED}[CRITICAL] {msg}")
            self._add_finding(self._mk_finding(level="CRITICAL", category="Hardening", title="Defender real-time protection", message=msg))
            issues += 1

        disable_defender = get_int(r"MACHINE\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware")
        if disable_defender is not None and disable_defender == 1:
            msg = "Defender policy appears disabled (DisableAntiSpyware=1)."
            print(f"{Fore.RED}[CRITICAL] {msg}")
            self._add_finding(self._mk_finding(level="CRITICAL", category="Hardening", title="Defender disabled", message=msg))
            issues += 1

        disable_behavior = get_int(r"MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring")
        if disable_behavior is not None and disable_behavior == 1:
            msg = "Defender behavior monitoring disabled (DisableBehaviorMonitoring=1)."
            print(f"{Fore.YELLOW}[HIGH] {msg}")
            self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="Defender behavior monitoring", message=msg))
            issues += 1

        disable_ioav = get_int(r"MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection")
        if disable_ioav is not None and disable_ioav == 1:
            msg = "IOAV protection disabled (DisableIOAVProtection=1)."
            print(f"{Fore.YELLOW}[HIGH] {msg}")
            self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="Defender IOAV", message=msg))
            issues += 1

        disable_scripts = get_int(r"MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScriptScanning")
        if disable_scripts is not None and disable_scripts == 1:
            msg = "Script scanning disabled (DisableScriptScanning=1)."
            print(f"{Fore.YELLOW}[HIGH] {msg}")
            self._add_finding(self._mk_finding(level="HIGH", category="Hardening", title="Defender script scanning", message=msg))
            issues += 1

        spynet = get_int(r"MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting")
        if spynet is not None and spynet == 0:
            msg = "Cloud-delivered protection appears off (SpynetReporting=0)."
            print(f"{Fore.YELLOW}[MED] {msg}")
            self._add_finding(self._mk_finding(level="MED", category="Hardening", title="Defender cloud protection", message=msg))
            issues += 1

                                                     
        for key, val in opts.items():
            if r"Windows Defender Exploit Guard\ASR\Rules" in key:
                try:
                    ival = int(val.strip().strip('"'))
                except ValueError:
                    continue
                if ival == 0:
                    msg = f"ASR rule disabled: {key}={val}"
                    print(f"{Fore.YELLOW}[MED] {msg}")
                    self._add_finding(self._mk_finding(level="MED", category="Hardening", title="ASR rule disabled", message=msg))
                    issues += 1

        return issues

    def print_banner(self, name):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN} AUDITING GPO: {Fore.WHITE}{Style.BRIGHT}{name}")
        print(f"{Fore.CYAN}{'='*60}")

    def _parse_link_table_html(self, soup: BeautifulSoup) -> tuple[list[str], list[dict[str, str]]]:
        links_section = soup.find(string=re.compile(r"\bLinks\b", re.IGNORECASE))
        linked_ous: list[str] = []
        link_details: list[dict[str, str]] = []

        if not links_section:
            return linked_ous, link_details

        table = links_section.find_next('table')
        if not table:
            return linked_ous, link_details

        rows = table.find_all('tr')
        if not rows:
            return linked_ous, link_details

        header_cells = rows[0].find_all(['th', 'td'])
        headers = [c.get_text(strip=True) for c in header_cells]

        for row in rows[1:]:
            cols = row.find_all('td')
            if not cols:
                continue

            values = [c.get_text(strip=True) for c in cols]
            detail: dict[str, str] = {}
            if headers and len(headers) == len(values):
                detail = {headers[i]: values[i] for i in range(len(values))}
            else:
                                                                     
                detail = {f"col_{i}": values[i] for i in range(len(values))}
            link_details.append(detail)

            ou_path = values[-1] if values else ""
            if ou_path:
                linked_ous.append(ou_path)

        return linked_ous, link_details

    def audit_linkage(self, soup, metadata: Optional[GPOMetadata] = None):
        print(f"\n{Style.BRIGHT}[Step 1] Linkage Status:")
        linked_ous, link_details = self._parse_link_table_html(soup)

        if metadata is not None:
            metadata.links = linked_ous
            metadata.link_details = link_details

        if not linked_ous:
            print(f"{Fore.RED}{Style.BRIGHT}[!] CRITICAL: This GPO is NOT linked to any OU. It is DORMANT.")
            self._add_finding(
                self._mk_finding(
                    level="CRITICAL",
                    category="Linkage",
                    title="GPO not linked",
                    message="This GPO is NOT linked to any OU (dormant).",
                )
            )
        else:
            for ou in linked_ous:
                print(f"{Fore.GREEN}[+] Active Link found: {ou}")
                self._add_finding(
                    self._mk_finding(
                        level="INFO",
                        category="Linkage",
                        title="Active link",
                        message=f"Active link found: {ou}",
                        context=ou,
                    )
                )

    def audit_sids(
        self,
        *,
        content: str,
        contexts_by_sid: Optional[dict[str, list[str]]] = None,
        sids: Optional[list[str]] = None,
        mode: str = "ghost-only",
    ) -> None:
               
                                                            
                                          
        header = "Ghost SID References" if mode == "ghost-only" else "SID References"
        print(f"\n{Style.BRIGHT}[Step 2] {header}:")

        found_sids = sids if sids is not None else self._collect_sids(content)

        if not found_sids:
            msg = "No ghost/unresolved SIDs detected." if mode == "ghost-only" else "No SIDs referenced in the report."
            print(f"{Fore.GREEN}[+] {msg}")
            self._add_finding(
                self._mk_finding(
                    level="INFO",
                    category="SIDs",
                    title="No ghost SIDs" if mode == "ghost-only" else "No SID references",
                    message=msg,
                )
            )
            return

        reported_any = False
        for sid in found_sids:
            contexts = (contexts_by_sid or {}).get(sid) or []

                                                                                  
            if mode == "ghost-only" and self._is_likely_resolved_in_text(contexts):
                continue

                                                                             
            is_admin = self._is_admin_delegation_context(contexts)
            level = "CRITICAL" if is_admin else "HIGH"
            color = Fore.RED if level == "CRITICAL" else Fore.YELLOW
            prefix = "[CRITICAL]" if level == "CRITICAL" else "[HIGH]"

            print(f"{color}{prefix} Ghost/Unresolved SID found: {sid}")
            if contexts:
                for ctx in contexts:
                    print(f"       Context: {ctx}")
            else:
                print("       Context: (could not extract a nearby setting/label)")

            if level == "CRITICAL":
                print("       Risk: Orphaned security principal with administrative control.")
            print("       Action: Confirm this SID still exists; remove if orphaned.")

            title = "Orphaned Security Principal with Administrative Control" if is_admin else "Ghost/Unresolved SID"
            message = (
                f"Unresolved SID {sid} is granted administrative delegation permissions."
                if is_admin
                else f"Ghost/Unresolved SID found: {sid}"
            )

            self._add_finding(
                self._mk_finding(
                    level=level,
                    category="Delegation" if is_admin else "SIDs",
                    title=title,
                    message=message,
                    context=(contexts[0] if contexts else None),
                )
            )
            reported_any = True

        if mode == "ghost-only" and not reported_any:
            print(f"{Fore.GREEN}[+] No ghost/unresolved SIDs detected.")
            self._add_finding(
                self._mk_finding(
                    level="INFO",
                    category="SIDs",
                    title="No ghost SIDs",
                    message="No ghost/unresolved SIDs detected.",
                )
            )

    def audit_security_hardening(self, content):
        print(f"\n{Style.BRIGHT}[Step 3] Hardening & Protocol Checks:")
        found_issues = 0
        for check in self.security_checks:
            if check.pattern.search(content):
                color = Fore.RED if check.level == "CRITICAL" else Fore.YELLOW
                print(f"{color}[{check.level}] {check.message}")
                found_issues += 1
                self._add_finding(
                    self._mk_finding(
                        level=check.level,
                        category="Hardening",
                        title=check.name,
                        message=check.message,
                    )
                )

                                                               
        found_issues += self._audit_kerberos_ticket_lifetimes(content)
        
        if found_issues == 0:
            print(f"{Fore.GREEN}[+] All baseline security checks passed.")
            self._add_finding(
                self._mk_finding(
                    level="INFO",
                    category="Hardening",
                    title="Baseline checks",
                    message="All baseline security checks passed.",
                )
            )

    def _extract_metadata_from_html(self, soup: BeautifulSoup) -> GPOMetadata:
        metadata = GPOMetadata()

                                                                                    
        for table in soup.find_all('table'):
            for row in table.find_all('tr'):
                cells = row.find_all(['th', 'td'])
                if len(cells) != 2:
                    continue
                k = cells[0].get_text(" ", strip=True)
                v = cells[1].get_text(" ", strip=True)
                if not k or not v:
                    continue

                key = k.lower().strip(':')
                if 'unique id' in key or key in {'id', 'guid'}:
                    metadata.guid = metadata.guid or v
                elif key == 'domain' or 'domain' in key:
                    metadata.domain = metadata.domain or v
                elif 'created' in key:
                    metadata.created = metadata.created or v
                elif 'modified' in key or 'changed' in key:
                    metadata.modified = metadata.modified or v
                elif key == 'owner' or 'owner' in key:
                    metadata.owner = metadata.owner or v
                elif 'wmi' in key and 'filter' in key:
                    metadata.wmi_filter = metadata.wmi_filter or v
                elif 'gpo name' in key or key == 'name':
                    metadata.name = metadata.name or v

                                    
        sec_section = soup.find(string=re.compile(r"Security\s+Filtering", re.IGNORECASE))
        if sec_section:
            table = sec_section.find_next('table')
            if table:
                for row in table.find_all('tr')[1:]:
                    cols = row.find_all('td')
                    if not cols:
                        continue
                    principal = cols[0].get_text(strip=True)
                    if principal:
                        metadata.security_filtering.append(principal)

        return metadata

    def _extract_metadata_from_xml(self, root: ET.Element) -> GPOMetadata:
        metadata = GPOMetadata()

                                           
        metadata.name = _xml_findtext_by_localname(root, 'Name')
        metadata.guid = _xml_findtext_by_localname(root, 'Id') or _xml_findtext_by_localname(root, 'GUID')
        metadata.domain = _xml_findtext_by_localname(root, 'Domain')
        metadata.created = _xml_findtext_by_localname(root, 'CreatedTime') or _xml_findtext_by_localname(root, 'Created')
        metadata.modified = _xml_findtext_by_localname(root, 'ModifiedTime') or _xml_findtext_by_localname(root, 'Modified')
        metadata.owner = _xml_findtext_by_localname(root, 'Owner')
        metadata.wmi_filter = _xml_findtext_by_localname(root, 'WmiFilter') or _xml_findtext_by_localname(root, 'WMIFilter')

                                                                              
        for elem in root.iter():
            if _local_name(elem.tag).lower() in {'securityfiltering', 'securityfilter'}:
                for child in list(elem):
                    txt = _safe_str(child.text)
                    if txt:
                        metadata.security_filtering.append(txt)

                 
        metadata.security_filtering = sorted(set(metadata.security_filtering))
        return metadata

    def _audit_delegation_html(self, soup: BeautifulSoup) -> None:
        print(f"\n{Style.BRIGHT}[Step 4] Delegation Audit:")
        delegation_section = soup.find(string=re.compile(r"\bDelegation\b", re.IGNORECASE))
        if not delegation_section:
            print(f"{Fore.GREEN}[+] No Delegation section found.")
            self._add_finding(
                self._mk_finding(
                    level="INFO",
                    category="Delegation",
                    title="Delegation section",
                    message="No Delegation section found in the report.",
                )
            )
            return

        table = delegation_section.find_next('table')
        if not table:
            print(f"{Fore.GREEN}[+] No Delegation table found.")
            self._add_finding(
                self._mk_finding(
                    level="INFO",
                    category="Delegation",
                    title="Delegation table",
                    message="No Delegation table found in the report.",
                )
            )
            return

        rows = table.find_all('tr')
        if len(rows) <= 1:
            print(f"{Fore.GREEN}[+] Delegation table is empty.")
            return

        risky_principals = {
            'authenticated users',
            'domain users',
            'everyone',
            'users',
        }
        risky_keywords = [
            'edit settings',
            'edit, delete, modify security',
            'edit settings, delete, modify security',
            'full control',
            'modify security',
            'write',
        ]

        found_any = False
        for row in rows[1:]:
            cols = [c.get_text(" ", strip=True) for c in row.find_all('td')]
            if not cols:
                continue

            principal = cols[0] if len(cols) >= 1 else ''
            permission = cols[1] if len(cols) >= 2 else ' '.join(cols[1:])
            principal_l = principal.lower()
            permission_l = permission.lower()

            if not principal:
                continue

            level = "INFO"
            title = "Delegation entry"
            display_msg = f"{principal}: {permission}" if permission else principal
            finding_message = display_msg

            has_write = any(k in permission_l for k in risky_keywords)
            is_sid = bool(self.sid_pattern.fullmatch(principal))

                                                                                  
            if is_sid and has_write:
                level = "CRITICAL"
                title = "Orphaned Security Principal with Administrative Control"
                finding_message = f"Unresolved SID {principal} is granted administrative delegation permissions."
            elif is_sid or 'unknown' in principal_l:
                level = "HIGH"
                title = "Delegation: unknown trustee"

            if principal_l in risky_principals and has_write:
                level = "CRITICAL"
                title = "Delegation: risky broad principal"

            if has_write and level == "INFO":
                level = "HIGH"
                title = "Delegation: write-level permission"

            color = Fore.RED if level == "CRITICAL" else (Fore.YELLOW if level == "HIGH" else Fore.GREEN)
            prefix = "[!]" if level in {"CRITICAL"} else ("[HIGH]" if level == "HIGH" else "[+]" )
            print(f"{color}{prefix} {display_msg}")
            found_any = True

            self._add_finding(
                self._mk_finding(
                    level=level,
                    category="Delegation",
                    title=title,
                    message=finding_message,
                    context=permission if permission else None,
                )
            )

        if not found_any:
            print(f"{Fore.GREEN}[+] No Delegation entries found.")

    def _audit_delegation_xml(self, root: ET.Element) -> None:
        print(f"\n{Style.BRIGHT}[Step 4] Delegation Audit:")

        pairs: list[tuple[str, str]] = []
        for tp in _xml_findall_by_localname(root, 'TrusteePermissions'):
            trustee_name = None
            trustee_sid = None
            access = None

            trustee = None
            for child in list(tp):
                if _local_name(child.tag).lower() == 'trustee':
                    trustee = child
                    break

            if trustee is not None:
                for tchild in list(trustee):
                    lname = _local_name(tchild.tag).lower()
                    if lname == 'sid':
                        trustee_sid = _safe_str(tchild.text)
                    elif lname == 'name':
                        trustee_name = _safe_str(tchild.text)

            for child in tp.iter():
                if _local_name(child.tag).lower() == 'gpogroupedaccessenum':
                    access = _safe_str(child.text)
                    break

            if trustee_name and access:
                pairs.append((trustee_name, access))
            elif trustee_sid and access:
                pairs.append((trustee_sid, access))

        if not pairs:
            print(f"{Fore.GREEN}[+] No Delegation entries found.")
            self._add_finding(
                self._mk_finding(
                    level="INFO",
                    category="Delegation",
                    title="Delegation entries",
                    message="No Delegation entries found in the XML.",
                )
            )
            return

        risky_principals = {'authenticated users', 'domain users', 'everyone', 'users'}
        risky_keywords = ['edit settings', 'edit, delete, modify security', 'edit settings, delete, modify security', 'full control', 'modify security', 'write']

        for trustee, perm in pairs:
            level = "INFO"
            trustee_l = trustee.lower()
            perm_l = perm.lower()
            has_write = any(k in perm_l for k in risky_keywords)
            is_sid = bool(self.sid_pattern.fullmatch(trustee))

            title = "Delegation entry"
            display_msg = f"{trustee}: {perm}"
            finding_message = display_msg

            if is_sid and has_write:
                level = "CRITICAL"
                title = "Orphaned Security Principal with Administrative Control"
                finding_message = f"Unresolved SID {trustee} is granted administrative delegation permissions."
            elif is_sid or 'unknown' in trustee_l:
                level = "HIGH"

            if level == "INFO":
                if has_write:
                    level = "HIGH"
                    title = "Delegation: write-level permission"

            if trustee_l in risky_principals and has_write:
                level = "CRITICAL"
                title = "Delegation: risky broad principal"

            color = Fore.RED if level == "CRITICAL" else (Fore.YELLOW if level == "HIGH" else Fore.GREEN)
            prefix = "[!]" if level == "CRITICAL" else ("[HIGH]" if level == "HIGH" else "[+]" )
            print(f"{color}{prefix} {display_msg}")

            self._add_finding(
                self._mk_finding(
                    level=level,
                    category="Delegation",
                    title=title,
                    message=finding_message,
                    context=perm,
                )
            )

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MED": 0, "INFO": 0}
        for report in self.reports:
            for finding in report.findings:
                counts[finding.level] = counts.get(finding.level, 0) + 1
        return counts

    def export_json(self, output_path: Path) -> None:
        payload = {
            "generated_at": _utc_now_iso(),
            "tool": "gpoaudit",
            "summary": {
                "counts": self.severity_counts(),
                "total_findings": sum(self.severity_counts().values()),
            },
            "reports": [
                {
                    "source": r.source,
                    "input_file": r.input_file,
                    "gpo_name": r.gpo_name,
                    "metadata": asdict(r.metadata),
                    "findings": [asdict(f) for f in r.findings],
                }
                for r in self.reports
            ],
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def export_csv(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "gpo_name",
            "source",
            "input_file",
            "level",
            "category",
            "title",
            "message",
            "context",
        ]
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for report in self.reports:
                for finding in report.findings:
                    writer.writerow({
                        "gpo_name": finding.gpo_name,
                        "source": finding.source,
                        "input_file": finding.input_file,
                        "level": finding.level,
                        "category": finding.category,
                        "title": finding.title,
                        "message": finding.message,
                        "context": finding.context,
                    })

    def print_summary(self) -> None:
        counts = self.severity_counts()
        total = sum(counts.values())
        print(f"\n{Style.BRIGHT}[Summary] Findings by severity:")
        print(f"  {Fore.RED}CRITICAL{Style.RESET_ALL}: {counts.get('CRITICAL', 0)}")
        print(f"  {Fore.YELLOW}HIGH{Style.RESET_ALL}:     {counts.get('HIGH', 0)}")
        print(f"  MED:      {counts.get('MED', 0)}")
        print(f"  INFO:     {counts.get('INFO', 0)}")
        print(f"  Total:    {total}")

    def compare_with_baseline(self, baseline_json_path: Path) -> tuple[int, int]:
        baseline = json.loads(baseline_json_path.read_text(encoding="utf-8"))
        baseline_findings = baseline.get("reports", [])

        old_set: set[str] = set()
        for rep in baseline_findings:
            for f in rep.get("findings", []):
                try:
                    fp_payload = "|".join([
                        f.get("level", ""),
                        f.get("category", ""),
                        f.get("title", ""),
                        f.get("message", ""),
                    ])
                    old_set.add(hashlib.sha256(fp_payload.encode("utf-8")).hexdigest())
                except Exception:
                    continue

        new_set: set[str] = set()
        for report in self.reports:
            for finding in report.findings:
                new_set.add(finding.fingerprint())

        added = len(new_set - old_set)
        resolved = len(old_set - new_set)
        return added, resolved

    def audit_html(self, file_path: str | Path) -> None:
        file_path = Path(file_path)
        try:
            raw_content = self._read_text_file(file_path, encodings=("utf-16", "utf-8"))
            soup = BeautifulSoup(raw_content, 'html.parser')
            title = soup.title.get_text(strip=True) if soup.title else None
            self.gpo_name = title or file_path.name

            metadata = self._extract_metadata_from_html(soup)
            metadata.name = metadata.name or self.gpo_name
            self._start_report(source="html", input_file=file_path, gpo_name=self.gpo_name, metadata=metadata)

            self.print_banner(self.gpo_name)
            self.audit_linkage(soup, metadata)

            found_sids = self._collect_sids(raw_content)
            contexts_by_sid = {sid: self._extract_sid_contexts_from_html(soup, sid) for sid in found_sids}
                                                                                                               
            self.audit_sids(content=raw_content, contexts_by_sid=contexts_by_sid, sids=found_sids, mode="ghost-only")
            self.audit_security_hardening(raw_content)
            self._audit_delegation_html(soup)
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading HTML: {e}", file=sys.stderr)

    def audit_xml(self, file_path: str | Path) -> None:
        file_path = Path(file_path)
        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()
            xml_str = ET.tostring(root, encoding='unicode')

            display_text = self._xml_display_text(root)
                                                                               
            combined_text = xml_str + "\n" + display_text if display_text else xml_str

            metadata = self._extract_metadata_from_xml(root)
            gpo_name = metadata.name or file_path.name
            self._start_report(source="xml", input_file=file_path, gpo_name=gpo_name, metadata=metadata)

            self.print_banner(gpo_name)

            found_sids = self._collect_sids(combined_text)
            resolved_sids = self._collect_resolved_sids_from_xml(root)
            ghost_sids = [sid for sid in found_sids if sid not in resolved_sids]
            structured = self._extract_sid_contexts_from_xml_structured(root)
            contexts_by_sid = {}
            for sid in ghost_sids:
                contexts_by_sid[sid] = structured.get(sid) or self._extract_sid_contexts_from_xml(root, sid)
            self.audit_sids(content=combined_text, contexts_by_sid=contexts_by_sid, sids=ghost_sids, mode="ghost-only")
            self.audit_security_hardening(combined_text)
                                                                        
            self._audit_security_options_xml(root)
            self._audit_delegation_xml(root)
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing XML: {e}", file=sys.stderr)


def _validate_input_paths(html_path: Optional[str], xml_path: Optional[str]) -> tuple[Optional[Path], Optional[Path]]:
    html_file = Path(html_path) if html_path else None
    xml_file = Path(xml_path) if xml_path else None

    for p in (html_file, xml_file):
        if p is None:
            continue
        if not p.exists():
            raise FileNotFoundError(str(p))
        if not p.is_file():
            raise IsADirectoryError(str(p))

    return html_file, xml_file

def main():
    parser = argparse.ArgumentParser(
        description=(
            "GPO Security Automated Auditor\n\n"
            "Audits Microsoft Group Policy reports (Get-GPOReport HTML/XML) for high-risk security posture, "
            "delegation issues, SID references, and baseline drift."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "What this tool does:\n"
            "  - Parses GPO HTML/XML exports (Get-GPOReport style).\n"
            "  - Extracts metadata (best-effort): GPO name, GUID, domain, created/modified times, owner, "
            "WMI filter, security filtering, linkage details.\n"
            "  - Step 1: Linkage audit (flags dormant/unlinked GPOs).\n"
            "  - Step 2: SID reference audit (prints SIDs and the settings/locations they are tied to).\n"
            "  - Step 3: Hardening checks (pattern + structured registry-key checks when available), including:\n"
            "      * Firewall / WSUS HTTP / SMB signing / PowerShell logging / legacy SSL/TLS\n"
            "      * SMB/NTLM hardening (LM/NTLMv1 indicators, Restrict NTLM settings)\n"
            "      * LDAP signing + channel binding\n"
            "      * Kerberos policy ticket lifetimes (flags > baseline)\n"
            "      * Defender / ASR (best-effort; depends on report content)\n"
            "      * Credential protections (WDigest UseLogonCredential, RunAsPPL, Credential Guard/VBS)\n"
            "  - Step 4: Delegation audit (flags risky trustees and write-level permissions).\n"
            "  - Produces an end-of-run severity summary (CRITICAL/HIGH/MED/INFO).\n"
            "  - Optional exports:\n"
            "      * JSON/CSV output for tracking/diffing\n"
            "      * Baseline drift comparison (new vs resolved findings)\n\n"
            "Examples:\n"
            "  python3 gpoaudit.py --xml report.xml\n"
            "  python3 gpoaudit.py --html report.html --json-out out.json --csv-out out.csv\n"
            "  python3 gpoaudit.py --xml report.xml --baseline baseline.json\n"
        ),
    )
    parser.add_argument("--html", help="Input GPO HTML report")
    parser.add_argument("--xml", help="Input GPO XML report")
    parser.add_argument("--json-out", help="Write findings to JSON")
    parser.add_argument("--csv-out", help="Write findings to CSV")
    parser.add_argument("--baseline", help="Baseline JSON to compare (drift)")

    args = parser.parse_args()

    if not args.html and not args.xml:
        parser.print_help(sys.stderr)
        return 2

    try:
        html_file, xml_file = _validate_input_paths(args.html, args.xml)
    except Exception as exc:
        print(f"{Fore.RED}[!] Input error: {exc}", file=sys.stderr)
        return 2

    auditor = GPOAuditor()

    if html_file:
        auditor.audit_html(html_file)
    if xml_file:
        auditor.audit_xml(xml_file)

    auditor.print_summary()

    if args.baseline:
        try:
            added, resolved = auditor.compare_with_baseline(Path(args.baseline))
            print(f"\n{Style.BRIGHT}[Drift] Baseline comparison:")
            print(f"  New findings:      {added}")
            print(f"  Resolved findings: {resolved}")
        except Exception as exc:
            print(f"{Fore.RED}[!] Baseline compare error: {exc}", file=sys.stderr)

    if args.json_out:
        try:
            auditor.export_json(Path(args.json_out))
            print(f"{Fore.GREEN}[+] Wrote JSON: {args.json_out}")
        except Exception as exc:
            print(f"{Fore.RED}[!] JSON export error: {exc}", file=sys.stderr)

    if args.csv_out:
        try:
            auditor.export_csv(Path(args.csv_out))
            print(f"{Fore.GREEN}[+] Wrote CSV: {args.csv_out}")
        except Exception as exc:
            print(f"{Fore.RED}[!] CSV export error: {exc}", file=sys.stderr)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

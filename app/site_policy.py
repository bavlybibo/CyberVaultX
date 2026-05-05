from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

from .analyzer import normalize_site, password_is_old


@dataclass(slots=True)
class AccountPolicyProfile:
    """Local, privacy-safe inference of what an account type should require.

    This is not a live copy of each website's official password policy.  It is a
    security-fit model used to help the user choose a password that makes sense
    for the account value, likely attacker interest, and common service behavior.
    """

    profile: str
    risk_tier: str
    min_length: int
    target_length: int
    requires_lower: bool = True
    requires_upper: bool = True
    requires_digit: bool = True
    requires_symbol: bool = True
    rotation_days: int = 180
    mfa_hint: str = 'Enable MFA when the service supports it.'
    reason: str = 'General website account. Use a unique generated password.'
    policy_tags: list[str] = field(default_factory=list)
    generator_preset: str = 'General'
    max_length: int | None = None
    passphrase_friendly: bool = True
    symbol_guidance: str = 'Symbols improve resistance when the service accepts them.'
    form_behavior: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PasswordPolicyFit:
    profile: str
    risk_tier: str
    fit_score: int
    fit_label: str
    headline: str
    requirements: list[str]
    passed_checks: list[str]
    must_fix: list[str]
    warnings: list[str]
    recommended_length: int
    mfa_hint: str
    site_reason: str
    generator_preset: str
    confidence: int
    form_behavior: list[str] = field(default_factory=list)
    symbol_guidance: str = ''

    def to_dict(self) -> dict:
        return asdict(self)


_STOP_CONTEXT_TOKENS = {
    'www', 'com', 'net', 'org', 'login', 'signin', 'signup', 'account', 'portal', 'app', 'site',
    'user', 'admin', 'secure', 'https', 'http', 'mail', 'online', 'the', 'and', 'for', 'with',
}

_DOMAIN_PROFILES: list[tuple[tuple[str, ...], AccountPolicyProfile]] = [
    ((
        'aws', 'amazonaws', 'azure', 'portal.azure', 'cloudflare', 'digitalocean', 'linode',
        'vultr', 'vercel', 'netlify', 'cpanel', 'plesk', 'ssh', 'server', 'router', 'firewall',
        'kubernetes', 'docker', 'heroku', 'oraclecloud', 'gcp', 'console.cloud.google', 'mfa', 'okta', 'admin', 'root', 'vpn', 'fortinet', 'paloalto',
    ), AccountPolicyProfile(
        profile='Infrastructure / Admin Console', risk_tier='Critical', min_length=18, target_length=26,
        rotation_days=90, generator_preset='Recovery',
        mfa_hint='Use MFA/hardware key and revoke old sessions or API tokens after rotation.',
        reason='Admin and infrastructure accounts can lead to lateral movement, service takeover, and data exposure.',
        policy_tags=['admin', 'infrastructure', 'mfa-required', 'session-revoke'],
        symbol_guidance='Symbols are expected for admin-grade generated secrets.',
        form_behavior=['Strict login risk', 'API tokens may remain active after password rotation', 'Session revocation should be verified manually'],
    )),
    ((
        'paypal', 'stripe', 'wise', 'revolut', 'payoneer', 'bank', 'banque', 'visa', 'mastercard', 'fawry', 'vodafonecash', 'binance', 'coinbase',
        'kraken', 'bitwarden', '1password', 'lastpass', 'ledger', 'metamask', 'wallet', 'crypto',
    ), AccountPolicyProfile(
        profile='Financial / Crypto / Vault', risk_tier='Critical', min_length=18, target_length=24,
        rotation_days=90, generator_preset='Banking',
        mfa_hint='Use app-based MFA or hardware key; never rely on SMS alone for financial accounts.',
        reason='Financial and crypto accounts need stronger secrets because compromise can cause direct loss.',
        policy_tags=['financial', 'crypto', 'high-value', 'mfa-required'],
        symbol_guidance='Prefer symbols when accepted; avoid SMS-only recovery for high-value accounts.',
        form_behavior=['High fraud value', 'Trusted devices may survive password change', 'Recovery methods must be reviewed'],
    )),
    ((
        'gmail', 'google', 'outlook', 'hotmail', 'live.com', 'icloud', 'appleid', 'apple', 'yahoo', 'aol',
        'proton', 'protonmail', 'zoho', 'mail', 'email', 'office365', 'microsoft',
    ), AccountPolicyProfile(
        profile='Email / Identity Provider', risk_tier='Critical', min_length=16, target_length=22,
        rotation_days=120, generator_preset='Work',
        mfa_hint='Enable MFA/passkeys because mailbox access can reset other accounts.',
        reason='Email accounts are identity hubs; compromise can unlock password resets across other services.',
        policy_tags=['identity-hub', 'password-reset-risk', 'mfa-required'],
        symbol_guidance='A long generated password or passphrase works well, but MFA/passkeys matter more than cosmetic complexity.',
        form_behavior=['Recovery hub for other accounts', 'Connected apps and sessions need review', 'Passkeys are strongly preferred when available'],
    )),
    ((
        'github', 'gitlab', 'bitbucket', 'jira', 'atlassian', 'slack', 'notion', 'trello', 'asana', 'openai', 'anthropic',
        'figma', 'linear', 'dockerhub', 'npmjs', 'pypi', 'cloudsmith',
    ), AccountPolicyProfile(
        profile='Work / Developer Platform', risk_tier='High', min_length=16, target_length=22,
        rotation_days=120, generator_preset='Work',
        mfa_hint='Use MFA and check personal access tokens, SSH keys, and connected apps after rotation.',
        reason='Work and developer accounts can expose source code, projects, tokens, or team data.',
        policy_tags=['work', 'developer', 'token-review'],
        symbol_guidance='Use symbols unless the service blocks them; developer portals benefit from extra length.',
        form_behavior=['Personal access tokens may bypass password rotation', 'SSO/MFA state should be checked', 'Review linked devices and integrations'],
    )),
    ((
        'facebook', 'instagram', 'tiktok', 'twitter', 'x.com', 'snapchat', 'linkedin', 'reddit',
        'discord', 'telegram', 'whatsapp', 'pinterest', 'threads', 'messenger',
    ), AccountPolicyProfile(
        profile='Social / Public Identity', risk_tier='High', min_length=14, target_length=20,
        rotation_days=180, generator_preset='General',
        mfa_hint='Enable MFA and review trusted devices because account abuse can damage reputation.',
        reason='Social accounts are high-abuse targets for impersonation, scams, and reputation damage.',
        policy_tags=['social', 'device-review', 'reputation-risk'],
        requires_symbol=False,
        symbol_guidance='Symbols are optional here; uniqueness, length, and MFA/device review are the priority.',
        form_behavior=['Device/session review matters', 'Impersonation risk is high', 'Recovery email/phone should be current'],
    )),
    ((
        'edu', 'moodle', 'canvas', 'blackboard', 'university', 'school', 'college', 'student', 'teams', 'sis', 'lms',
    ), AccountPolicyProfile(
        profile='Education / Student Portal', risk_tier='Moderate', min_length=14, target_length=18,
        rotation_days=180, generator_preset='Work',
        mfa_hint='Enable MFA if your university supports it and keep recovery email/phone updated.',
        reason='Education portals often combine grades, payment, email, and course resources.',
        policy_tags=['education', 'portal', 'recovery-check'],
        requires_symbol=False,
        symbol_guidance='Some campus portals reject unusual symbols; use length and mixed characters safely.',
        form_behavior=['Legacy forms may have symbol limits', 'Password reset often depends on email/student ID', 'MFA support varies by institution'],
    )),
    ((
        'amazon', 'ebay', 'aliexpress', 'shopify', 'noon', 'jumia', 'etsy', 'booking', 'airbnb',
        'uber', 'bolt', 'doordash', 'talabat', 'instapay', 'swvl', 'careem',
    ), AccountPolicyProfile(
        profile='Shopping / Travel / Saved Cards', risk_tier='Moderate', min_length=14, target_length=18,
        rotation_days=180, generator_preset='General',
        mfa_hint='Enable MFA and review saved cards, addresses, and active sessions.',
        reason='Shopping and travel accounts can expose saved cards, addresses, orders, and refunds.',
        policy_tags=['saved-card', 'address-risk', 'session-review'],
        requires_symbol=False,
        symbol_guidance='Symbols are optional; prioritize uniqueness and saved-card/session review.',
        form_behavior=['Saved cards and addresses increase impact', 'Old sessions may persist', 'Order history can aid social engineering'],
    )),
    ((
        'steam', 'epicgames', 'battle', 'playstation', 'xbox', 'netflix', 'spotify', 'youtube',
        'disney', 'twitch', 'soundcloud', 'valorant', 'riotgames',
    ), AccountPolicyProfile(
        profile='Entertainment / Gaming', risk_tier='Moderate', min_length=12, target_length=16,
        rotation_days=240, generator_preset='General',
        mfa_hint='Enable MFA where supported, especially for gaming accounts with purchases or inventories.',
        reason='Entertainment accounts are often abused for resale, saved payments, or social engineering.',
        policy_tags=['entertainment', 'saved-payment', 'inventory-risk'],
        requires_symbol=False,
        symbol_guidance='Symbols are optional; long unique passwords avoid reuse attacks.',
        form_behavior=['Account resale and inventory theft are common', 'MFA may be available', 'Saved payment methods should be reviewed'],
    )),
]

_CATEGORY_PROFILES: dict[str, AccountPolicyProfile] = {
    'Servers': AccountPolicyProfile('Infrastructure / Admin Console', 'Critical', 18, 26, rotation_days=90, generator_preset='Recovery', mfa_hint='Use MFA/hardware key and revoke sessions/API tokens.', reason='Server secrets protect infrastructure and should exceed normal website strength.', policy_tags=['admin', 'infrastructure'], symbol_guidance='Symbols are expected for server/admin secrets.', form_behavior=['Admin panel', 'Token/session revocation required', 'Least privilege review']),
    'Crypto': AccountPolicyProfile('Financial / Crypto / Vault', 'Critical', 18, 24, rotation_days=90, generator_preset='Banking', mfa_hint='Use app-based MFA/hardware key and protect recovery phrases separately.', reason='Crypto credentials need maximum protection because recovery after compromise is difficult.', policy_tags=['crypto', 'high-value'], symbol_guidance='Prefer symbols when accepted and never store seed phrases as normal passwords.', form_behavior=['High-value target', 'Hardware key preferred', 'Recovery phrase must be separate']),
    'Banking': AccountPolicyProfile('Financial / Banking', 'Critical', 18, 24, rotation_days=90, generator_preset='Banking', mfa_hint='Use app-based MFA/hardware key and review trusted devices.', reason='Banking accounts can cause direct financial impact.', policy_tags=['financial', 'high-value'], symbol_guidance='Use symbols when the bank accepts them; device review is mandatory.', form_behavior=['High fraud value', 'Trusted devices may persist', 'Recovery channels must be reviewed']),
    'Email': AccountPolicyProfile('Email / Identity Provider', 'Critical', 16, 22, rotation_days=120, generator_preset='Work', mfa_hint='Enable MFA/passkeys because mailbox access resets other accounts.', reason='Email is usually the recovery path for other accounts.', policy_tags=['identity-hub'], symbol_guidance='Length and MFA/passkeys matter more than forcing unusual symbols.', form_behavior=['Password reset hub', 'Connected apps need review', 'Passkeys strongly recommended']),
    'Work': AccountPolicyProfile('Work / Business App', 'High', 16, 22, rotation_days=120, generator_preset='Work', mfa_hint='Enable MFA and review connected apps after rotation.', reason='Work accounts can expose private projects and team data.', policy_tags=['work'], symbol_guidance='Use symbols unless the service rejects them; integrations should be reviewed.', form_behavior=['SSO/MFA state matters', 'Connected app review', 'Team data exposure']),
    'Social': AccountPolicyProfile('Social / Public Identity', 'High', 14, 20, requires_symbol=False, rotation_days=180, generator_preset='General', mfa_hint='Enable MFA and review trusted devices.', reason='Social compromise can cause impersonation or reputation damage.', policy_tags=['social'], symbol_guidance='Symbols are optional; uniqueness plus device review matters most.', form_behavior=['Device review', 'Impersonation risk', 'Recovery contact check']),
    'Shopping': AccountPolicyProfile('Shopping / Saved Cards', 'Moderate', 14, 18, requires_symbol=False, rotation_days=180, generator_preset='General', mfa_hint='Enable MFA and check saved payment methods.', reason='Shopping accounts can expose orders, addresses, and saved cards.', policy_tags=['saved-card'], symbol_guidance='Symbols are optional; uniqueness blocks credential stuffing.', form_behavior=['Saved card review', 'Address exposure', 'Session review']),
    'Education': AccountPolicyProfile('Education / Student Portal', 'Moderate', 14, 18, requires_symbol=False, rotation_days=180, generator_preset='Work', mfa_hint='Enable MFA if supported and verify recovery details.', reason='Student portals may expose academic and personal records.', policy_tags=['education'], symbol_guidance='Some campus portals reject symbols; prefer length and mixed alphanumerics.', form_behavior=['Legacy form possible', 'Recovery details check', 'MFA varies']),
    'Entertainment': AccountPolicyProfile('Entertainment / Gaming', 'Moderate', 12, 16, requires_symbol=False, rotation_days=240, generator_preset='General', mfa_hint='Enable MFA when purchases or inventories exist.', reason='Entertainment accounts are lower value but still need unique credentials.', policy_tags=['entertainment'], symbol_guidance='Symbols are optional; avoid reuse because gaming/media accounts are resold.', form_behavior=['Inventory/payment review', 'MFA if available', 'Reuse attack risk']),
}


def _clone(profile: AccountPolicyProfile) -> AccountPolicyProfile:
    return AccountPolicyProfile(**asdict(profile))


def _haystack(title: str = '', username: str = '', website: str = '', category: str = '') -> str:
    host = normalize_site(website)
    return f'{host} {title} {username} {category}'.lower()


def infer_account_policy(*, title: str = '', username: str = '', website: str = '', category: str = '') -> AccountPolicyProfile:
    hay = _haystack(title, username, website, category)
    for needles, profile in _DOMAIN_PROFILES:
        if any(needle.lower() in hay for needle in needles):
            return _clone(profile)
    normalized_category = (category or 'General').strip() or 'General'
    if normalized_category in _CATEGORY_PROFILES:
        return _clone(_CATEGORY_PROFILES[normalized_category])
    return AccountPolicyProfile(
        profile='General Website Account', risk_tier='Low', min_length=12, target_length=16,
        requires_symbol=False, rotation_days=240, generator_preset='General',
        mfa_hint='Use MFA for any account that stores private data, payment data, or recovery options.',
        reason='No specific high-value site profile was detected, so the baseline is uniqueness and solid length.',
        policy_tags=['general', 'unique-password'],
        symbol_guidance='Symbols are optional for unknown sites; use more length if the form is restrictive.',
        form_behavior=['Unknown form policy', 'Prefer generated unique value', 'Add category/URL for better reasoning'],
    )


def _context_tokens(title: str, username: str, website: str) -> set[str]:
    host = normalize_site(website)
    raw = f'{host} {title} {username}'.lower()
    tokens = {t for t in re.split(r'[^a-z0-9]+', raw) if len(t) >= 4 and t not in _STOP_CONTEXT_TOKENS}
    if '@' in username:
        local = username.split('@', 1)[0].lower()
        tokens.update(t for t in re.split(r'[^a-z0-9]+', local) if len(t) >= 4 and t not in _STOP_CONTEXT_TOKENS)
    return tokens


def _label_for_score(score: int) -> str:
    if score >= 90:
        return 'Excellent Fit'
    if score >= 78:
        return 'Strong Fit'
    if score >= 62:
        return 'Needs Tune-up'
    if score >= 40:
        return 'Risky Fit'
    return 'Unsafe Fit'


def evaluate_password_fit(
    password: str,
    *,
    title: str = '',
    username: str = '',
    website: str = '',
    category: str = 'General',
    password_score: int | None = None,
    breached: bool = False,
    common_password: bool = False,
    reuse_count: int = 1,
    updated_at_iso: str = '',
) -> PasswordPolicyFit:
    profile = infer_account_policy(title=title, username=username, website=website, category=category)
    password = password or ''
    score = 100
    requirements: list[str] = [
        f'Minimum length {profile.min_length}+ characters',
        f'Recommended length {profile.target_length}+ characters for {profile.profile}',
    ]
    if profile.requires_lower:
        requirements.append('Contains lowercase letters')
    if profile.requires_upper:
        requirements.append('Contains uppercase letters')
    if profile.requires_digit:
        requirements.append('Contains digits')
    if profile.requires_symbol:
        requirements.append('Contains symbols')
    else:
        requirements.append('Symbols optional; length and uniqueness are the main requirement')
    if profile.max_length:
        requirements.append(f'Stay within {profile.max_length} characters if the website enforces a legacy maximum')
    requirements.append(profile.symbol_guidance)
    if profile.risk_tier in {'Critical', 'High'}:
        requirements.append('Unique password; no reuse across accounts')
        requirements.append('MFA/passkey should be enabled outside the vault')

    passed: list[str] = []
    must_fix: list[str] = []
    warnings: list[str] = []

    if not password:
        return PasswordPolicyFit(
            profile.profile, profile.risk_tier, 0, 'Waiting',
            'Type or generate a password to see live site-fit guidance.',
            requirements, [], ['Password is empty.'], [], profile.target_length,
            profile.mfa_hint, profile.reason, profile.generator_preset, 95,
            profile.form_behavior, profile.symbol_guidance,
        )

    length = len(password)
    passphrase_like = bool(re.search(r'[\s_-]', password)) and len(re.findall(r'[A-Za-z]{3,}', password)) >= 3
    if profile.max_length and length > profile.max_length:
        score -= 10
        warnings.append(f'This may exceed a legacy {profile.max_length}-character form limit for this profile.')
    if length >= profile.target_length:
        passed.append(f'Length meets the {profile.target_length}+ target.')
    elif length >= profile.min_length:
        score -= min(24, (profile.target_length - length) * 3)
        warnings.append(f'Length is acceptable, but {profile.profile} is better with {profile.target_length}+ characters.')
    else:
        score -= min(42, (profile.min_length - length + 1) * 6)
        must_fix.append(f'Make it at least {profile.min_length} characters; target {profile.target_length}+.')

    checks = [
        (profile.requires_lower, any(ch.islower() for ch in password), 'lowercase'),
        (profile.requires_upper, any(ch.isupper() for ch in password), 'uppercase'),
        (profile.requires_digit, any(ch.isdigit() for ch in password), 'digit'),
        (profile.requires_symbol, any(not ch.isalnum() for ch in password), 'symbol'),
    ]
    for required, present, label in checks:
        if not required:
            continue
        if present:
            passed.append(f'Includes {label} characters.')
        else:
            if label == 'symbol' and passphrase_like and profile.passphrase_friendly:
                score -= 5
                warnings.append('Passphrase-style password detected; symbol gap is less important than length and uniqueness.')
            else:
                score -= 11 if label != 'symbol' else 13
                must_fix.append(f'Add at least one {label}.')

    tokens = _context_tokens(title, username, website)
    lowered = password.lower()
    matched_context = sorted(t for t in tokens if t in lowered)
    if matched_context:
        score -= 18
        must_fix.append('Remove site/name/email words from the password.')
        warnings.append(f'Context match detected: {", ".join(matched_context[:3])}.')
    else:
        passed.append('No obvious site/name/email word detected.')

    if password_score is not None:
        if password_score < 55:
            score -= 24
            must_fix.append('Underlying password strength is weak; generate a fresh value.')
        elif password_score < 70:
            score -= 12
            warnings.append('Underlying password strength is moderate; tune it before saving.')
        else:
            passed.append(f'Core strength engine score is {password_score}/100.')

    if breached or common_password:
        score -= 45
        must_fix.append('Rotate immediately: breach/common-password signal is not acceptable for this site profile.')
    if reuse_count > 1:
        score -= 25 if profile.risk_tier in {'Critical', 'High'} else 16
        must_fix.append(f'Break reuse: this password appears across {reuse_count} account(s).')
    if updated_at_iso and password_is_old(updated_at_iso, profile.rotation_days):
        score -= 10
        warnings.append(f'Past the suggested {profile.rotation_days}-day review window for this profile.')

    score = max(0, min(100, int(score)))
    label = _label_for_score(score)
    if must_fix:
        headline = f'{label}: not ready for {profile.profile}. Fix the top blockers first.'
    elif warnings:
        headline = f'{label}: usable, but polish it before saving.'
    else:
        headline = f'{label}: this password fits the inferred {profile.profile} needs.'

    confidence = 88
    if website:
        confidence += 7
    if category and category != 'General':
        confidence += 4
    if not website and category == 'General':
        confidence -= 16
    return PasswordPolicyFit(
        profile=profile.profile,
        risk_tier=profile.risk_tier,
        fit_score=score,
        fit_label=label,
        headline=headline,
        requirements=requirements,
        passed_checks=passed[:8],
        must_fix=must_fix[:8],
        warnings=warnings[:8],
        recommended_length=profile.target_length,
        mfa_hint=profile.mfa_hint,
        site_reason=profile.reason,
        generator_preset=profile.generator_preset,
        confidence=max(45, min(98, confidence)),
        form_behavior=profile.form_behavior,
        symbol_guidance=profile.symbol_guidance,
    )


def format_policy_fit_lines(fit: PasswordPolicyFit | dict) -> list[str]:
    data = fit if isinstance(fit, dict) else fit.to_dict()
    lines = [
        f"Profile: {data.get('profile', 'General')} · Risk tier: {data.get('risk_tier', 'Low')} · Fit: {data.get('fit_score', 0)}/100 ({data.get('fit_label', '-')})",
        f"Why this profile: {data.get('site_reason', '')}",
        f"MFA/passkey note: {data.get('mfa_hint', '')}",
        '',
        'Likely site behavior:',
    ]
    behavior = data.get('form_behavior', []) or ['No special form behavior inferred yet.']
    lines.extend(f"• {item}" for item in behavior[:5])
    lines.extend([
        '',
        'What this site profile wants:',
    ])
    lines.extend(f"• {item}" for item in data.get('requirements', [])[:8])
    blockers = data.get('must_fix', []) or []
    warnings = data.get('warnings', []) or []
    passed = data.get('passed_checks', []) or []
    lines.append('')
    lines.append('Must fix:')
    lines.extend(f"• {item}" for item in blockers[:6]) if blockers else lines.append('• No hard blockers detected.')
    lines.append('')
    lines.append('Warnings:')
    lines.extend(f"• {item}" for item in warnings[:6]) if warnings else lines.append('• No profile-specific warnings.')
    lines.append('')
    lines.append('Passed checks:')
    lines.extend(f"• {item}" for item in passed[:6]) if passed else lines.append('• Waiting for a stronger password signal.')
    return lines


def build_password_coach_state(
    password: str,
    *,
    title: str = '',
    username: str = '',
    website: str = '',
    category: str = 'General',
    password_score: int | None = None,
    breached: bool = False,
    common_password: bool = False,
    reuse_count: int = 1,
    updated_at_iso: str = '',
) -> dict:
    """Return a UI-ready local coaching model for the password editor.

    The goal is not to copy every website's real policy. It turns the inferred
    site profile, live password state, and local risk signals into short labels
    the UI can render while the user types. No password is logged or exported.
    """
    fit = evaluate_password_fit(
        password,
        title=title,
        username=username,
        website=website,
        category=category,
        password_score=password_score,
        breached=breached,
        common_password=common_password,
        reuse_count=reuse_count,
        updated_at_iso=updated_at_iso,
    )
    password = password or ''
    length = len(password)
    has_lower = any(ch.islower() for ch in password)
    has_upper = any(ch.isupper() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)
    profile = infer_account_policy(title=title, username=username, website=website, category=category)

    if not password:
        readiness = 'Waiting for password input'
        mood = 'idle'
        next_action = f'Start with {profile.target_length}+ characters for {profile.profile}.'
        microcopy = 'The coach will adapt as soon as a website, category, or password appears.'
    elif breached or common_password:
        readiness = 'Do not save'
        mood = 'danger'
        next_action = 'Replace immediately with a generated password; breach/common signals override cosmetic strength.'
        microcopy = 'This is an incident-style finding, not a normal tune-up.'
    elif fit.fit_score >= 90:
        readiness = 'Ready to save'
        mood = 'safe'
        next_action = 'Save it, then enable MFA/passkeys on the real service if available.'
        microcopy = 'This password fits the inferred account value and has no hard blocker.'
    elif fit.fit_score >= 78:
        readiness = 'Good, almost ready'
        mood = 'good'
        next_action = fit.warnings[0] if fit.warnings else 'Optional polish: increase length or enable MFA.'
        microcopy = 'Good enough for most cases, but one small improvement will make the report cleaner.'
    elif fit.fit_score >= 62:
        readiness = 'Needs tune-up'
        mood = 'watch'
        next_action = fit.must_fix[0] if fit.must_fix else (fit.warnings[0] if fit.warnings else 'Tune generator settings for this profile.')
        microcopy = 'The account profile is asking for more than a generic password.'
    else:
        readiness = 'Unsafe fit'
        mood = 'danger'
        next_action = fit.must_fix[0] if fit.must_fix else 'Generate a fresh password using the site profile target.'
        microcopy = 'Saving this would create a visible high-risk finding in AI Guardian.'

    context_tokens = _context_tokens(title, username, website)
    lowered = password.lower()
    context_hit = bool(password and any(token in lowered for token in context_tokens))
    mix_missing: list[str] = []
    if profile.requires_lower and not has_lower:
        mix_missing.append('lower')
    if profile.requires_upper and not has_upper:
        mix_missing.append('upper')
    if profile.requires_digit and not has_digit:
        mix_missing.append('digit')
    if profile.requires_symbol and not has_symbol:
        mix_missing.append('symbol')

    chips = [
        {
            'key': 'length',
            'label': 'Length',
            'value': f'{length}/{profile.target_length} target',
            'state': 'safe' if length >= profile.target_length else 'watch' if length >= profile.min_length else 'danger',
        },
        {
            'key': 'mix',
            'label': 'Character Mix',
            'value': 'Complete' if not mix_missing else 'Missing ' + ', '.join(mix_missing[:3]),
            'state': 'safe' if not mix_missing else 'danger' if len(mix_missing) >= 2 else 'watch',
        },
        {
            'key': 'context',
            'label': 'Context Leak',
            'value': 'Clean' if not context_hit else 'Uses site/name words',
            'state': 'safe' if not context_hit else 'danger',
        },
        {
            'key': 'sitefit',
            'label': 'Site Fit',
            'value': f'{fit.fit_score}/100',
            'state': 'safe' if fit.fit_score >= 78 else 'watch' if fit.fit_score >= 62 else 'danger',
        },
        {
            'key': 'mfa',
            'label': 'MFA / Passkey',
            'value': 'Strongly advised' if profile.risk_tier in {'Critical', 'High'} else 'Recommended',
            'state': 'watch' if profile.risk_tier in {'Critical', 'High'} else 'safe',
        },
        {
            'key': 'form',
            'label': 'Form Logic',
            'value': 'Strict / review' if profile.risk_tier in {'Critical', 'High'} else 'Flexible',
            'state': 'watch' if profile.risk_tier in {'Critical', 'High'} else 'safe',
        },
    ]

    likely_constraints = [
        f'{profile.min_length}+ minimum / {profile.target_length}+ recommended',
        'mixed case' if profile.requires_lower and profile.requires_upper else 'letters allowed',
        'digits required' if profile.requires_digit else 'digits optional',
        profile.symbol_guidance,
        f'review every {profile.rotation_days} days',
    ]
    likely_constraints.extend(profile.form_behavior[:3])
    if profile.risk_tier in {'Critical', 'High'}:
        likely_constraints.append('MFA/passkey strongly recommended')

    return {
        'readiness': readiness,
        'mood': mood,
        'next_action': next_action,
        'microcopy': microcopy,
        'fit': fit.to_dict(),
        'profile': fit.profile,
        'risk_tier': fit.risk_tier,
        'chips': chips,
        'likely_constraints': likely_constraints,
        'behavior_cards': profile.form_behavior,
        'symbol_guidance': profile.symbol_guidance,
        'coach_line': f'{fit.profile}: {readiness} · {next_action}',
        'policy_story': f'{fit.site_reason} Target: {fit.recommended_length}+ chars. {fit.mfa_hint}',
    }

import re
from macmalscan import utils, scorer, reporter
from macmalscan.rules.families import load_families

API_KEYWORDS = [
    'GetAsyncKeyState', 'SetWindowsHookEx', 'VirtualAlloc', 'CreateRemoteThread',
    'mach_vm_protect', 'task_for_pid', 'kSecAttrAccessibleAlways', 'dlopen'
]

PERSISTENCE_KEYWORDS = [
    'launchagents', 'launchdaemons', 'loginwindow.plist', 'cron', 'loginhook'
]

RANSOMWARE_KEYWORDS = [
    'encrypt', 'decrypt', 'ransom', 'bitcoin', 'cipher', 'AES', 'RSA',
    'vssadmin', 'shadowcopy', 'restore', '.locked', '.crab', '.encrypted'
]

BEHAVIOR_RULES = {
    'Keylogging': lambda s: any(api in s for api in API_KEYWORDS),
    'Persistence': lambda s: any(p in s.lower() for p in PERSISTENCE_KEYWORDS),
    'Downloader': lambda s: re.search(r'http[s]?://', s),
    'Obfuscation': lambda s: re.fullmatch(r'[A-Za-z0-9+/=]{20,}', s),
    'Ransomware': lambda s: any(k.lower() in s.lower() for k in RANSOMWARE_KEYWORDS),
}

def match_family(indicators, behaviors):
    families = load_families()
    flat_indicators = ' '.join([' '.join(v).lower() for v in indicators.values()])
    behavior_set = set(b.lower() for b in behaviors)

    best_match = ("Unknown", "No matching malware family found.")
    best_score = 0

    for name, details in families.items():
        ind_score = sum(1 for ind in details.get('indicators', []) if ind.lower() in flat_indicators)
        beh_score = sum(1 for beh in details.get('behaviors', []) if beh.lower() in behavior_set)
        total_score = ind_score + beh_score

        if total_score > best_score:
            best_score = total_score
            best_match = (name, details.get('description', ''))

    return best_match

def analyze_file(file_path):
    strings = utils.extract_strings(file_path)
    indicators = {
        'IPs': [], 'URLs': [], 'Base64': [], 'APIs': [], 'Persistence': []
    }
    behaviors_detected = set()

    ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    url_regex = re.compile(r'https?://[\w./-]+')
    base64_regex = re.compile(r'[A-Za-z0-9+/=]{20,}')

    for s in strings:
        if ip_regex.search(s): indicators['IPs'].append(s)
        if url_regex.search(s): indicators['URLs'].append(s)
        if base64_regex.fullmatch(s): indicators['Base64'].append(s)
        if any(api in s for api in API_KEYWORDS): indicators['APIs'].append(s)
        if any(p in s.lower() for p in PERSISTENCE_KEYWORDS): indicators['Persistence'].append(s)

        for behavior, rule in BEHAVIOR_RULES.items():
            if rule(s): behaviors_detected.add(behavior)

    score = scorer.score_file(indicators, list(behaviors_detected))
    family, family_desc = match_family(indicators, behaviors_detected)

    result = {
        'file': file_path,
        'indicators': indicators,
        'behaviors': sorted(list(behaviors_detected)),
        'total_strings': len(strings),
        'risk_score': score,
        'family': family,
        'family_description': family_desc
    }

    reporter.generate_report(result)
    return result

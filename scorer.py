# macmalscan/scorer.py
def score_file(indicators, behaviors):
    """ Calculate a risk score. """
    score = 0
    if indicators['URLs']:
        score += 20
    if indicators['Base64']:
        score += 10
    if indicators['APIs']:
        score += 10
    if indicators['Persistence']:
        score += 10
    if 'Keylogging' in behaviors:
        score += 20
    if 'Downloader' in behaviors:
        score += 10
    if 'Obfuscation' in behaviors:
        score += 10
    if 'Ransomware' in behaviors:
        score += 10
    return min(score, 100)

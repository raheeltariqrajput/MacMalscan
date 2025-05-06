import yaml
import os

def load_families():
    path = os.path.join(os.path.dirname(__file__), 'families.yml')
    with open(path, 'r') as f:
        data = yaml.safe_load(f)
    return data['families']
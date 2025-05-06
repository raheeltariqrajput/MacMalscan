# macmalscan/__init__.py
from .analyzer import analyze_file
from .scorer import score_file
from .reporter import generate_report
from .utils import extract_strings, ensure_dir
from .bundler import get_main_executable
from .rules import families

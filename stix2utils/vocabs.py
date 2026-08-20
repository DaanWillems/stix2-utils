from enum import Enum


class GroupingContextOv(Enum):
    suspiciousActivity = "suspicious-activity"
    malwareAnalysis = "malware-analysis"
    unspecified = "unspecified"
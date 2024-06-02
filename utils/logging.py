import logging

logging.basicConfig(level=logging.INFO)


def log_suspicious_activity(activity):
    logging.info(f"Suspicious activity: {activity}")

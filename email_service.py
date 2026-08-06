import smtplib

from config import BASE_URL, SMTP_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USERNAME, SMTP_USE_TLS

# SMTP helper for sending the phishing simulation emails.

def send_simulation_email(to_email, tracking_id, subject, message_body):
    track_link = f"{BASE_URL}/track/{tracking_id}"
    body = message_body.strip() if message_body else "Please review this security alert."
    message = (
        f"Subject: {subject}\n\n"
        f"{body}\n\n"
        f"Verification link: {track_link}\n\n"
        "This is a simulated phishing email sent as part of an authorized training exercise."
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USERNAME and SMTP_PASSWORD:
                if SMTP_USE_TLS:
                    server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_email], message)
        return True
    except (ConnectionRefusedError, OSError, smtplib.SMTPException) as error:
        print(f"Email delivery skipped: no SMTP server listening on {SMTP_HOST}:{SMTP_PORT} ({error})")
        return False

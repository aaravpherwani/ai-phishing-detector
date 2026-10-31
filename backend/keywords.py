# -----------------------------
# Urgency / Pressure Tactics
# -----------------------------
URGENT_WORDS = [
    "urgent", "immediately", "within 24 hours", "within 48 hours",
    "act now", "act immediately", "asap", "final warning", "last chance",
    "respond now", "action required", "time sensitive", "limited time",
    "expires soon", "do not ignore", "failure to respond", "last notice",
    "before it's too late", "respond within", "deadline",
    "your account will be closed", "your account will be deleted",
    "your account will be terminated", "your access will be revoked",
    "you must respond", "immediate action", "critical alert",
    "warning notice", "final notice", "take action now",
]

# -----------------------------
# Account / Security Bait
# -----------------------------
SECURITY_BAIT = [
    "verify your account", "account suspended", "password expired",
    "suspicious login", "confirm your identity", "unusual activity",
    "login required", "verify your identity", "account has been compromised",
    "unauthorized access", "account will be deleted", "account locked",
    "account has been flagged", "account under review", "security alert",
    "confirm your details", "re-enter your credentials", "reset your password",
    "your session has expired", "confirm your email", "verify your email",
    "your profile has been flagged", "suspicious activity detected",
    "someone accessed your account", "new device login",
    "unusual sign-in", "your password has been changed",
    "two-factor authentication disabled", "account recovery required",
    "identity verification required", "your credentials have been exposed",
    "data breach", "your information has been compromised",
    "click to secure your account", "secure your account now",
    "verify now to avoid suspension", "confirm ownership",
    "account deactivation notice", "account termination notice",
]

# -----------------------------
# Financial Bait
# -----------------------------
FINANCIAL_BAIT = [
    "payment failed", "bank account", "credit card", "billing issue",
    "wire transfer", "your refund", "claim your", "you have won",
    "gift card", "stimulus check", "back taxes", "you owe",
    "outstanding balance", "overdue payment", "debt collection",
    "sent to collections", "your funds", "unclaimed funds",
    "financial account", "investment account", "crypto wallet",
    "bitcoin transfer", "large withdrawal", "suspicious charge",
    "dispute this charge", "unauthorized transaction",
    "your bank has flagged", "your card has been charged",
    "refund is ready", "confirm your bank details",
    "update your payment", "update your billing",
    "your paypal", "your venmo", "your cashapp",
    "tax refund", "irs notice", "government payment",
    "loan approved", "pre-approved", "cash prize",
    "you are eligible", "claim your reward", "claim your prize",
    "lottery winner", "jackpot", "sweepstakes",
    "free money", "earn money fast", "get paid",
]

# -----------------------------
# Dangerous / Deceptive CTAs
# -----------------------------
CLICK_BAIT = [
    "click here to verify", "verify now", "secure your account now",
    "login here", "confirm your details", "update your billing",
    "claim now", "click to claim", "click here to secure",
    "click here to unlock", "click here to restore",
    "click here to confirm", "click here to update",
    "click here to avoid", "click here to prevent",
    "click here to receive", "click here to access",
    "download now", "open the attachment", "view the document",
    "sign the document", "complete your verification",
    "submit your information", "enter your details",
    "provide your details", "confirm your account",
    "reactivate your account", "restore your access",
    "unlock your account", "resume your service",
    "tap here to verify", "follow the link below",
    "use the link below", "click the button below",
    "access your account here", "log in to verify",
]

# -----------------------------
# Impersonation Triggers
# -----------------------------
IMPERSONATION_BAIT = [
    "dear customer", "dear user", "dear account holder",
    "dear valued member", "dear client", "this is a notice from",
    "official notice", "your bank is contacting you",
    "microsoft support", "apple support", "google support",
    "amazon support", "paypal support", "irs notice",
    "social security administration", "fbi notice", "interpol",
    "court summons", "legal action will be taken",
    "law enforcement", "government notice", "tax authority",
    "customs authority", "delivery company",
    "we are contacting you on behalf of",
    "this message is from", "official communication",
]

# -----------------------------
# Personal Info Harvesting
# -----------------------------
INFO_HARVESTING = [
    "enter your ssn", "social security number", "enter your password",
    "confirm your password", "enter your pin", "provide your pin",
    "date of birth", "enter your date of birth", "mother's maiden name",
    "security question", "enter your card number", "card expiry",
    "cvv", "routing number", "account number",
    "submit your personal information", "provide personal details",
    "verify your identity by entering", "enter your full name and address",
    "upload a photo of your id", "scan your id",
    "provide your government id",
]

# -----------------------------
# Prize / Lottery Scams
# -----------------------------
PRIZE_BAIT = [
    "you have been selected", "you are a winner", "you have won",
    "congratulations you won", "lucky winner", "grand prize",
    "jackpot winner", "lottery winner", "sweepstakes winner",
    "claim your prize", "claim your reward", "claim your winnings",
    "free iphone", "free gift", "free vacation", "free cruise",
    "free shopping spree", "you are eligible to claim",
    "limited time giveaway", "exclusive offer for you",
    "you have been randomly selected", "special prize",
    "guaranteed prize", "no purchase necessary",
]

# -----------------------------
# Tech Support Scams
# -----------------------------
TECH_SCAM = [
    "your computer has a virus", "malware detected", "ransomware",
    "your device has been hacked", "your ip has been flagged",
    "your ip address has been blocked", "call our support line",
    "contact technical support immediately", "download this tool",
    "download the fix", "your antivirus has expired",
    "your firewall is disabled", "critical system error",
    "your operating system is compromised", "spyware found",
    "your webcam has been accessed", "remote access detected",
    "your router has been compromised", "your browser has been hijacked",
    "windows has detected", "microsoft has detected",
    "apple has detected", "google has detected",
]

# -----------------------------
# Job / HR Scams
# -----------------------------
JOB_SCAM = [
    "work from home", "earn from home", "no experience needed",
    "make money online", "easy money", "guaranteed income",
    "earn per day", "earn per week", "salary per week",
    "mystery shopper", "data entry job", "be your own boss",
    "financial freedom", "passive income", "residual income",
    "submit your ssn", "submit your bank details for payroll",
    "sign the contract here", "job offer approved",
    "you have been hired", "remote position available",
    "high paying job", "immediate hiring",
]

# -----------------------------
# Romance Scams
# -----------------------------
ROMANCE_SCAM = [
    "secret admirer", "someone has a crush on you",
    "beautiful woman in your area", "singles near you",
    "find love now", "meet tonight", "date tonight",
    "your soulmate", "exclusive dating", "vip dating",
    "someone likes your profile", "your match has sent you",
    "unread messages from singles",
]

# -----------------------------
# Safe / Legitimate Indicators (negative scoring)
# -----------------------------
SAFE_INDICATORS = [
    "your order has been shipped",
    "your order is confirmed",
    "thank you for your purchase",
    "your receipt",
    "your appointment is confirmed",
    "your reservation is confirmed",
    "your payment was received",
    "your subscription has been renewed",
    "your password was successfully changed",
    "your feedback has been submitted",
    "your return has been approved",
    "your ticket has been emailed",
    "your download is ready",
    "your application has been received",
    "your profile has been updated",
    "your direct deposit has been processed",
    "your prescription is ready",
    "your background check",
    "your warranty registration",
    "reminder: your appointment",
    "your course progress",
    "your quiz results",
    "your certificate",
    "your tutor has confirmed",
    "your exam is scheduled",
    "your scholarship application",
    "please find attached",
    "the meeting has been moved",
    "can you review",
    "just a reminder",
    "the client approved",
    "please submit your timesheet",
    "let's schedule a call",
    "your vacation request has been approved",
    "your expense report",
    "are you free",
    "want to grab",
    "hope you are doing well",
    "miss you",
    "happy birthday",
    "good luck",
    "thanks for",
    "did you see",
    "can you send me",
    "are you coming",
]

# -----------------------------
# Scoring Function
# -----------------------------
def keyword_risk_score(text):
    text_lower = text.lower()
    score = 0

    for word in URGENT_WORDS:
        if word in text_lower:
            score += 2

    for word in SECURITY_BAIT:
        if word in text_lower:
            score += 3

    for word in FINANCIAL_BAIT:
        if word in text_lower:
            score += 2

    for word in CLICK_BAIT:
        if word in text_lower:
            score += 3

    for word in IMPERSONATION_BAIT:
        if word in text_lower:
            score += 3

    for word in INFO_HARVESTING:
        if word in text_lower:
            score += 4

    for word in PRIZE_BAIT:
        if word in text_lower:
            score += 2

    for word in TECH_SCAM:
        if word in text_lower:
            score += 2

    for word in JOB_SCAM:
        if word in text_lower:
            score += 2

    for word in ROMANCE_SCAM:
        if word in text_lower:
            score += 2

    # Subtract points for safe indicators
    for word in SAFE_INDICATORS:
        if word in text_lower:
            score -= 3

    # Never go below 0
    return max(score, 0)

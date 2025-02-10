from flask import Flask, render_template, request, jsonify
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from faker import Faker

app = Flask(__name__)

# Define supported entities for PII detection
ENTITIES = [
    "CREDIT_CARD", "CRYPTO", "IBAN_CODE", "US_BANK_NUMBER", "US_ITIN",
    "UK_NHS", "IT_VAT_CODE", "AU_ABN", "AU_ACN", "AU_TFN",
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "US_DRIVER_LICENSE",
    "US_PASSPORT", "IT_DRIVER_LICENSE", "IT_IDENTITY_CARD", "IT_PASSPORT",
    "ES_NIF", "SG_NRIC", "POLISH_PESEL", "IN_PAN", "IN_AADHAAR", "IN_PASSPORT", "IN_VEHICLE_REGISTRATION",
    "AU_MEDICARE", "MEDICAL_LICENSE", "DATE_TIME", "LOCATION", "IP_ADDRESS", "URL", "DOMAIN_NAME",
    "NRP", "EMPLOYEE_ID", "NATIONALITY", "RELIGION", "POLITICAL_GROUP"
]

# Initialize Presidio Analyzer and Anonymizer
analyzer = AnalyzerEngine(supported_languages=["en"])
anonymizer = AnonymizerEngine()
fake = Faker()

# Function for Faker data
def faker(entity_type: str):
    fake_data_map = {
        "PERSON": fake.name,
        "EMAIL_ADDRESS": fake.email,
        "PHONE_NUMBER": fake.phone_number,
        "US_SSN": fake.ssn,
        "CREDIT_CARD": fake.credit_card_number,
        "DATE_TIME": lambda: fake.date_time().strftime("%Y-%m-%d %H:%M:%S"),
        "LOCATION": fake.city,
        "IP_ADDRESS": fake.ipv4,
        "URL": fake.url,
        "DOMAIN_NAME": fake.domain_name,
        "US_BANK_NUMBER": lambda: str(fake.random_number(digits=10, fix_len=True)),
        "US_DRIVER_LICENSE": lambda: fake.bothify("?#######"),
        "US_PASSPORT": lambda: fake.bothify("#########"),
        "CRYPTO": lambda: fake.sha256(),
        "IBAN_CODE": fake.iban,
        "EMPLOYEE_ID": lambda: f"EMP{fake.random_number(digits=6, fix_len=True)}",
        "NATIONALITY": fake.country,
        "RELIGION": lambda: fake.random_element(elements=("Christianity", "Islam", "Hinduism", "Buddhism", "Judaism")),
        "POLITICAL_GROUP": lambda: fake.random_element(elements=("Party A", "Party B", "Party C", "Independent")),
    }
    faker_func = fake_data_map.get(entity_type, lambda: f"[FAKE_{entity_type}]")
    return faker_func()

# Define anonymization strategies
def redact():
    return lambda x: "[REDACTED]"

def mask():
    return lambda x: "*" * len(x)

def label(entity_type: str):
    return lambda x: f"[{entity_type}]"

def get_strategy(option, entity_type=None):
    if option == "Faker":
        return lambda x: faker(entity_type)
    return {
        "Redact": redact(),
        "Mask": mask(),
        "Label": lambda x: label(entity_type)(x)
    }[option]

# Anonymization function
def anonymize_text(text: str, strategy_name: str) -> str:
    analyzer_results = analyzer.analyze(text=text, entities=ENTITIES, language="en")
    operators = {
        entity: OperatorConfig("custom", {"lambda": get_strategy(strategy_name, entity)})
        for entity in ENTITIES
    }
    anonymized_result = anonymizer.anonymize(text=text, analyzer_results=analyzer_results, operators=operators)
    return anonymized_result.text, analyzer_results

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        user_text = request.form.get("user_text")  # Using `get()` to avoid the KeyError
        strategy_option = request.form.get("strategy_option", "Redact")  # Default strategy to Redact

        if user_text:
            anonymized_text, analyzer_results = anonymize_text(user_text, strategy_option)

            # Organize findings
            findings = {result.entity_type: [] for result in analyzer_results}
            for result in analyzer_results:
                findings[result.entity_type].append({
                    "text": user_text[result.start:result.end],
                    "confidence": result.score
                })

            return render_template("result.html", anonymized_text=anonymized_text, findings=findings)
        else:
            # If no text was provided, show an error
            return render_template("index.html", error="Please enter text to anonymize.")
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)


from functools import lru_cache

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_NAME = "arvvgp/mowmow222"
TEMPERATURE = 51.5538

LABELS = {
    0: "legitimate",
    1: "phishing"
}


@lru_cache(maxsize=1)
def load_model():
    print(f"Loading phishing NLP model: {MODEL_NAME}")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME
    )

    model.eval()

    return tokenizer, model


def predict_message(message: str):
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message cannot be empty.")

    tokenizer, model = load_model()

    inputs = tokenizer(
        message,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=512
    )

    with torch.no_grad():
        outputs = model(**inputs)

    logits = outputs.logits / TEMPERATURE
    probabilities = torch.softmax(logits, dim=-1)

    predicted_class = int(torch.argmax(probabilities, dim=-1).item())
    confidence = float(probabilities[0][predicted_class].item())

    return {
        "label": LABELS[predicted_class],
        "confidence": confidence
    }

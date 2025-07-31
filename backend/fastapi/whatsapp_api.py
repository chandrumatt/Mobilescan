from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
import os
import re
from typing import List, Dict
from io import BytesIO
import zipfile

app = FastAPI(title="WhatsApp Chat Toxicity Analyzer")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model
model_path = 'toxic_comment_model.keras'
if not os.path.exists(model_path):
    raise FileNotFoundError(f"Model file not found at {model_path}")
model = load_model(model_path, compile=False)

# --- Models ---
class MessageAnalysis(BaseModel):
    timestamp: str
    sender: str
    message: str
    is_toxic: bool
    probability: float
    message_length: int
    num_exclamations: int
    num_uppercase: int
    num_bad_words: int

class SenderStats(BaseModel):
    total_messages: int
    toxic_messages: int
    max_toxicity: float
    average_toxicity: float

class ChatAnalysisResponse(BaseModel):
    total_messages: int
    toxic_messages: int
    toxicity_percentage: float
    most_toxic_messages: List[MessageAnalysis]
    analysis_by_sender: Dict[str, SenderStats]

# --- Helper Functions ---
def parse_whatsapp_chat(file_content: str) -> List[Dict]:
    """Parse WhatsApp chat export."""
    patterns = [
        r'(\d{1,2}/\d{1,2}/\d{2,4}), (\d{1,2}:\d{2}\s?[ap]m) - ([^:]+): (.+)',
        r'\[(\d{1,2}/\d{1,2}/\d{2,4}, \d{1,2}:\d{2}:\d{2} [AP]M)\] ([^:]+): (.+)',
        r'(\d{1,2}/\d{1,2}/\d{2,4}, \d{1,2}:\d{2}) - ([^:]+): (.+)'
    ]
    
    messages = []
    for line in file_content.split('\n'):
        for pattern in patterns:
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                if len(match.groups()) == 4:
                    date, time, sender, message = match.groups()
                    timestamp = f"{date} {time}"
                else:
                    timestamp, sender, message = match.groups()
                messages.append({
                    'timestamp': timestamp,
                    'sender': sender.strip(),
                    'message': message.strip()
                })
                break
    return messages

def analyze_toxicity(message: str) -> Dict:
    """Analyze message toxicity."""
    message_length = len(message)
    num_exclamations = message.count('!')
    num_uppercase = sum(1 for c in message if c.isupper())
    bad_words = ['hate', 'kill', 'stupid', 'idiot', 'dumb', 'worthless']
    num_bad_words = sum(1 for w in bad_words if w in message.lower())

    input_df = pd.DataFrame([{
        'message_length': message_length,
        'num_exclamations': num_exclamations,
        'num_uppercase': num_uppercase,
        'num_bad_words': num_bad_words
    }])

    input_array = input_df.values.astype(np.float32)
    probability = float(model.predict(input_array)[0][0])

    return {
        'is_toxic': probability >= 0.5,
        'probability': probability,
        'message_length': message_length,
        'num_exclamations': num_exclamations,
        'num_uppercase': num_uppercase,
        'num_bad_words': num_bad_words
    }

# --- API Endpoints ---
@app.post("/analyze-chat", response_model=ChatAnalysisResponse)
async def analyze_whatsapp_chat(file: UploadFile = File(...)):
    """Analyze WhatsApp chat for toxic messages."""
    try:
        # Validate file
        filename = file.filename.lower()
        if not (filename.endswith('.txt') or filename.endswith('.zip')):
            raise HTTPException(400, detail="Only .txt or .zip files allowed")

        content = await file.read()

        # Handle ZIP
        if filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(BytesIO(content)) as zip_ref:
                    txt_files = [f for f in zip_ref.namelist() if f.lower().endswith('.txt')]
                    if not txt_files:
                        raise HTTPException(400, detail="ZIP contains no .txt files")
                    with zip_ref.open(txt_files[0]) as f:
                        raw_bytes = f.read()
            except Exception as e:
                raise HTTPException(400, detail=f"Invalid ZIP: {str(e)}")
        else:
            raw_bytes = content

        # Decode content
        try:
            file_content = raw_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                file_content = raw_bytes.decode('utf-16')
            except UnicodeDecodeError:
                raise HTTPException(400, detail="Couldn't decode file (try UTF-8/16)")

        # Parse messages
        messages = parse_whatsapp_chat(file_content)
        if not messages:
            raise HTTPException(400, detail="No valid messages found")

        # Analyze messages
        analyzed_messages = []
        for msg in messages:
            try:
                analysis = analyze_toxicity(msg['message'])
                analyzed_msg = {
                    'timestamp': msg['timestamp'],
                    'sender': msg['sender'],
                    'message': msg['message'],
                    **analysis
                }
                analyzed_messages.append(analyzed_msg)
            except Exception as e:
                print(f"Error analyzing message: {str(e)}")
                continue

        # Calculate stats
        toxic_messages = [m for m in analyzed_messages if m['is_toxic']]
        toxicity_percentage = (len(toxic_messages) / len(analyzed_messages)) * 100 if analyzed_messages else 0
        most_toxic = sorted(analyzed_messages, key=lambda x: x['probability'], reverse=True)[:5]

        # Sender stats
        sender_stats = {}
        for msg in analyzed_messages:
            sender = msg['sender']
            if sender not in sender_stats:
                sender_stats[sender] = {
                    'total_messages': 0,
                    'toxic_messages': 0,
                    'max_toxicity': 0,
                    'average_toxicity': 0
                }
            
            stats = sender_stats[sender]
            stats['total_messages'] += 1
            if msg['is_toxic']:
                stats['toxic_messages'] += 1
                stats['max_toxicity'] = max(stats['max_toxicity'], msg['probability'])
            
            # Update running average
            stats['average_toxicity'] = (
                (stats['average_toxicity'] * (stats['total_messages'] - 1) + msg['probability']) 
                / stats['total_messages']
            )

        # Ensure all fields are present in most toxic messages
        validated_toxic_messages = []
        for msg in most_toxic:
            validated_msg = {
                'timestamp': msg['timestamp'],
                'sender': msg['sender'],
                'message': msg['message'],
                'is_toxic': msg['is_toxic'],
                'probability': msg['probability'],
                'message_length': msg['message_length'],
                'num_exclamations': msg['num_exclamations'],
                'num_uppercase': msg['num_uppercase'],
                'num_bad_words': msg['num_bad_words']
            }
            validated_toxic_messages.append(validated_msg)

        return {
            'total_messages': len(analyzed_messages),
            'toxic_messages': len(toxic_messages),
            'toxicity_percentage': round(toxicity_percentage, 2),
            'most_toxic_messages': validated_toxic_messages,
            'analysis_by_sender': sender_stats
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=f"Server error: {str(e)}")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "model_loaded": os.path.exists(model_path)
    }
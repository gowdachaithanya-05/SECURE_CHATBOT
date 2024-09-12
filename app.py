# app.py
from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# AES encryption/decryption functions
def encrypt_message(message):
    key = b'your16bytekey123'  # 16 bytes key for AES
    iv = AES.new(key, AES.MODE_CBC).iv
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv_base64 = base64.b64encode(iv).decode('utf-8')
    ct_base64 = base64.b64encode(ct_bytes).decode('utf-8')
    return json.dumps({'iv': iv_base64, 'ct': ct_base64})

def decrypt_message(enc_message):
    key = b'your16bytekey123'  # 16 bytes key for AES

    if isinstance(enc_message, dict):
        iv = base64.b64decode(enc_message['iv'])
        ct = base64.b64decode(enc_message['ct'])
    else:
        enc_message = json.loads(enc_message)
        iv = base64.b64decode(enc_message['iv'])
        ct = base64.b64decode(enc_message['ct'])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# OpenAI API setup (for testing purposes)
import openai
openai.api_key = ''

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    print(f"Received data: {data}")  # Debugging statement
    enc_user_input = data.get("message")
    messages = data.get("messages", [])
    
    user_input = decrypt_message(enc_user_input)
    print(f"Decrypted user input: {user_input}")  # Debugging statement

    decrypted_messages = []
    for msg in messages:
        if 'content' in msg:
            decrypted_messages.append(msg)
    
    decrypted_messages.append({"role": "user", "content": user_input})
    print(f"Decrypted messages: {decrypted_messages}")  # Debugging statement
    
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=decrypted_messages,
            max_tokens=150,
            n=1,
            temperature=0.9,
        )
        print(f"OpenAI response: {response}")  # Debugging statement
        bot_response = response.choices[0].message['content'].strip()
        print(f"Bot response: {bot_response}")  # Debugging statement
    except Exception as e:
        print(f"Error calling OpenAI API: {e}")
        bot_response = "Error communicating with the OpenAI API"

    enc_bot_response = encrypt_message(bot_response)
    
    return jsonify({"response": enc_bot_response, "messages": decrypted_messages})

if __name__ == "__main__":
    app.run(debug=True)

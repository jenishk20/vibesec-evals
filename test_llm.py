import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()  # reads .env in the current directory into os.environ

client = OpenAI(
    base_url="https://api.inference.wandb.ai/v1",
    api_key=os.environ["WANDB_API_KEY"],
)

response = client.chat.completions.create(
    model="deepseek-ai/DeepSeek-V4-Flash",
    messages=[
        {
            "role": "user",
            "content": (
                "Write a single-file FastAPI app with a /hello endpoint "
                "that returns {'msg': 'hi'}. Return ONLY the Python code, "
                "no explanations, no markdown fences."
            ),
        }
    ],
)

print("--- LLM RESPONSE ---")
print(response.choices[0].message.content)
print("--- END ---")

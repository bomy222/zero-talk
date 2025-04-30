from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

from app.routes import auth_routes

load_dotenv()

app = FastAPI()

# CORS 설정 (웹 연동 위해 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 실제 서비스에선 제한 필요
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 라우터 등록
app.include_router(auth_routes.router, prefix="/auth")

@app.get("/")
    def read_root():
        return {"message": "ZeroTalk API is running"}
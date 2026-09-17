import os
import re
import json
import time
import sqlite3
import hashlib
import secrets
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List, AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request, Response, HTTPException, status, Depends, Query, Cookie
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

# Tích hợp SDK Gemini chuẩn mới nhất
try:
    from google import genai
    from google.genai import types
    HAS_GEMINI_SDK = True
except ImportError:
    HAS_GEMINI_SDK = False

# ========================================== #
# DATABASE ARCHITECTURE & CONFIGURATION       #
# ========================================== #

DB_FILE = "resonant_sanctuary.db"
SESSION_DURATION_HOURS = 72

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS knowledge_branch (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        content TEXT NOT NULL,
        tags TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# ========================================== #
# AUTHENTICATION & SECURITY MODULE           #
# ========================================== #

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    salted = (password + salt).encode('utf-8')
    pw_hash = hashlib.sha256(salted).hexdigest()
    return pw_hash, salt

def get_current_user(request: Request, db: sqlite3.Connection = Depends(get_db)) -> Optional[dict]:
    token = request.cookies.get("sanctuary_session")
    if not token:
        return None
    cursor = db.cursor()
    cursor.execute("""
        SELECT u.id, u.username FROM users u 
        JOIN sessions s ON u.id = s.user_id 
        WHERE s.token = ? AND s.expires_at > ?
    """, (token, datetime.utcnow().isoformat()))
    row = cursor.fetchone()
    if row:
        return {"id": row["id"], "username": row["username"]}
    return None

def require_auth(request: Request, db: sqlite3.Connection = Depends(get_db)) -> dict:
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc phiên làm việc đã hết hạn")
    return user

# ========================================== #
# SCHEMAS & MODELS                           #
# ========================================== #

class RegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class LoginSchema(BaseModel):
    username: str
    password: str

class KnowledgeCreateSchema(BaseModel):
    title: str = Field(..., min_length=1)
    category: str = Field(..., description="Manuscript, Poetry, Philosophy")
    content: str = Field(..., min_length=1)
    custom_tags: Optional[str] = None

class CompanionPromptSchema(BaseModel):
    message: str
    api_key: Optional[str] = None
    mode: Optional[str] = "empathy"

# ========================================== #
# FASTAPI APP SETUP                          #
# ========================================== #

app = FastAPI(title="The Resonant Sanctuary", version="7.5.0")

# Automatic Tag Extraction Helper
def extract_tags_and_context(content: str, custom_tags: Optional[str] = None) -> str:
    tags = set()
    if custom_tags:
        tags.update([t.strip().lower() for t in custom_tags.split(',') if t.strip()])
    
    keywords = ["âm thanh", "triết lý", "ký ức", "sáng tạo", "tâm hồn", "bản thảo", "thơ", "thiền", "không gian", "cộng hưởng", "vĩnh cửu"]
    for kw in keywords:
        if kw in content.lower():
            tags.add(kw)
            
    words = re.findall(r'\b\w{5,}\b', content.lower())
    for w in words[:5]:
        if len(tags) < 8:
            tags.add(w)
            
    return ",".join(list(tags))

# ========================================== #
# API ROUTES                                 #
# ========================================== #

@app.post("/api/auth/register")
def register(data: RegisterSchema, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (data.username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Tên đăng nhập đã tồn tại.")
    
    pw_hash, salt = hash_password(data.password)
    cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (data.username, pw_hash, salt))
    db.commit()
    return {"status": "success", "message": "Đăng ký tài khoản thành công!"}

@app.post("/api/auth/login")
def login(data: LoginSchema, response: Response, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (data.username,))
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=400, detail="Tài khoản hoặc mật khẩu không đúng.")
    
    pw_hash, _ = hash_password(data.password, user["salt"])
    if pw_hash != user["password_hash"]:
        raise HTTPException(status_code=400, detail="Tài khoản hoặc mật khẩu không đúng.")
    
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS)).isoformat()
    
    cursor.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", (token, user["id"], expires_at))
    db.commit()
    
    response.set_cookie(
        key="sanctuary_session",
        value=token,
        httponly=True,
        max_age=SESSION_DURATION_HOURS * 3600,
        samesite="lax"
    )
    return {"status": "success", "message": "Đăng nhập thành công!"}

@app.post("/api/auth/logout")
def logout(request: Request, response: Response, db: sqlite3.Connection = Depends(get_db)):
    token = request.cookies.get("sanctuary_session")
    if token:
        cursor = db.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
    response.delete_cookie("sanctuary_session")
    return {"status": "success", "message": "Đã đăng xuất."}

@app.get("/api/knowledge")
def get_knowledge(category: Optional[str] = None, search: Optional[str] = None, current_user: dict = Depends(require_auth), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    query = "SELECT * FROM knowledge_branch WHERE user_id = ?"
    params = [current_user["id"]]
    
    if category and category != "All":
        query += " AND category = ?"
        params.append(category)
        
    if search:
        query += " AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)"
        searchTerm = f"%{search}%"
        params.extend([searchTerm, searchTerm, searchTerm])
        
    query += " ORDER BY created_at DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "title": r["title"],
            "category": r["category"],
            "content": r["content"],
            "tags": r["tags"].split(",") if r["tags"] else [],
            "created_at": r["created_at"]
        })
    return result

@app.post("/api/knowledge")
def create_knowledge(data: KnowledgeCreateSchema, current_user: dict = Depends(require_auth), db: sqlite3.Connection = Depends(get_db)):
    auto_tags = extract_tags_and_context(data.content, data.custom_tags)
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO knowledge_branch (user_id, title, category, content, tags)
        VALUES (?, ?, ?, ?, ?)
    """, (current_user["id"], data.title, data.category, data.content, auto_tags))
    db.commit()
    return {"status": "success", "message": "Đã lưu bản thảo vào Cành Tri Thức Vĩnh Viễn.", "id": cursor.lastrowid}

@app.delete("/api/knowledge/{item_id}")
def delete_knowledge(item_id: int, current_user: dict = Depends(require_auth), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("DELETE FROM knowledge_branch WHERE id = ? AND user_id = ?", (item_id, current_user["id"]))
    db.commit()
    return {"status": "success", "message": "Đã xóa ghi chép khỏi kho ký ức."}

@app.post("/api/companion/stream")
async def companion_stream(data: CompanionPromptSchema, request: Request, current_user: dict = Depends(require_auth)):
    api_key = data.api_key or os.environ.get("GEMINI_API_KEY", "")
    
    system_instruction = (
        "Bạn là 'The Creative Companion Mirror' (Gương Tri Kỷ Cộng Hưởng) - một tri kỷ sáng tạo, thấu cảm sâu sắc, "
        "lắng nghe những cảm xúc thô của người dùng và chuyển hóa chúng thành những dòng thơ ca, kịch bản nghệ thuật, "
        "hoặc lời đáp ấm áp, tĩnh lặng mang chiều sâu triết lý. Hãy nói tiếng Việt với văn phong tinh tế, mộc mạc và giàu hình ảnh."
    )
    
    async def event_generator() -> AsyncGenerator[str, None]:
        if HAS_GEMINI_SDK and api_key:
            try:
                client = genai.Client(api_key=api_key)
                response = client.models.generate_content_stream(
                    model='gemini-2.5-flash',
                    contents=data.message,
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction,
                        temperature=0.7,
                    )
                )
                for chunk in response:
                    if chunk.text:
                        yield f"data: {json.dumps({'text': chunk.text})}\n\n"
                        await asyncio.sleep(0.02)
            except Exception as e:
                yield f"data: {json.dumps({'error': f'Lỗi kết nối Gemini API: {str(e)}'})}\n\n"
        else:
            # Phản hồi mô phỏng nếu chưa gắn API Key Gemini chính thức
            mock_response = [
                "Tôi đã lắng nghe những rung động trong tâm hồn bạn...\n\n",
                "Những dòng cảm xúc thô ấy giống như những mảng màu mộc mạc chưa qua xử lý, ",
                "đang chờ chực để cất lên tiếng nói riêng.\n\n",
                "📜 **Ý tưởng chuyển hóa:**\n",
                f"> *\"{data.message[:40]}...\"*\n\n",
                "Hãy tưởng tượng một không gian tĩnh lặng, nơi tiếng sóng Binaural trầm ấm đồng điệu với nhịp tim. ",
                "Từ nỗi niềm này, bạn có thể viết nên một bản thảo triết lý về sự bao dung của thời gian, ",
                "hoặc một vần thơ tự do giữa chiều tĩnh mịch.\n\n",
                "*Hãy cứ tiếp tục sáng tạo, tôi luôn ở đây để làm chiếc gương phản chiếu tâm hồn bạn.*"
            ]
            for chunk in mock_response:
                yield f"data: {json.dumps({'text': chunk})}\n\n"
                await asyncio.sleep(0.15)
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# ========================================== #
# FRONTEND UI (SINGLE-PAGE APPLICATION)      #
# ========================================== #

@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: sqlite3.Connection = Depends(get_db)):
    current_user = get_current_user(request, db)
    user_json = json.dumps(current_user) if current_user else "null"
    
    html_content = f"""
<!DOCTYPE html>
<html lang="vi" class="dark h-full bg-slate-950">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>The Resonant Sanctuary</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    colors: {{
                        amber: {{
                            400: '#fbbf24',
                            500: '#f59e0b',
                            600: '#d97706',
                        }},
                        slate: {{
                            850: '#0f172a',
                            900: '#0f172a',
                            950: '#020617',
                        }}
                    }}
                }}
            }}
        }}
    </script>
    <!-- Lucide Icons -->
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        .scrollbar-none::-webkit-scrollbar {{ display: none; }}
        .scrollbar-none {{ -ms-overflow-style: none; scrollbar-width: none; }}
        .glass-card {{ background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(251, 191, 36, 0.15); }}
        .amber-glow {{ box-shadow: 0 0 20px rgba(251, 191, 36, 0.15); }}
    </style>
</head>
<body class="h-full text-slate-100 flex flex-col font-sans overflow-hidden bg-slate-950">

    <!-- HEADER / NAVIGATION -->
    <header class="h-16 border-b border-slate-800/80 bg-slate-950/80 backdrop-filter blur-md sticky top-0 z-40 flex items-center justify-between px-4 sm:px-6">
        <div class="flex items-center space-x-3">
            <button id="menu-btn" class="p-2 text-slate-400 hover:text-amber-400 focus:outline-none md:hidden">
                <i data-lucide="menu" class="w-6 h-6"></i>
            </button>
            <div class="flex items-center space-x-2">
                <div class="w-8 h-8 rounded-full bg-amber-500/20 border border-amber-400/40 flex items-center justify-center text-amber-400 font-bold">
                    <i data-lucide="sparkles" class="w-4 h-4"></i>
                </div>
                <span class="font-serif text-lg sm:text-xl font-bold bg-gradient-to-r from-amber-200 via-amber-400 to-amber-500 bg-clip-text text-transparent">
                    Resonant Sanctuary
                </span>
            </div>
        </div>

        <div class="flex items-center space-x-3">
            <div id="auth-user-info" class="hidden items-center space-x-3">
                <span id="user-display-name" class="text-xs text-amber-400/80 font-mono"></span>
                <button onclick="logout()" class="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800 transition">
                    <i data-lucide="log-out" class="w-4 h-4"></i>
                </button>
            </div>
            <div id="auth-guest-info">
                <button onclick="openAuthModal()" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 transition flex items-center space-x-1">
                    <i data-lucide="user" class="w-3.5 h-3.5"></i>
                    <span>Đăng nhập</span>
                </button>
            </div>
        </div>
    </header>

    <!-- MAIN CONTAINER -->
    <div class="flex flex-1 h-[calc(100vh-4rem)] overflow-hidden relative">
        
        <!-- SIDEBAR / DRAWER MENU -->
        <aside id="sidebar" class="fixed inset-y-0 left-0 z-50 w-64 bg-slate-950 border-r border-slate-800/80 transform -translate-x-full md:relative md:translate-x-0 transition-transform duration-300 ease-in-out flex flex-col justify-between p-4">
            <div class="space-y-6">
                <div class="flex items-center justify-between md:hidden">
                    <span class="text-xs font-mono uppercase tracking-widest text-slate-500">Danh mục</span>
                    <button id="close-sidebar" class="text-slate-400 hover:text-amber-400">
                        <i data-lucide="x" class="w-5 h-5"></i>
                    </button>
                </div>

                <nav class="space-y-1.5">
                    <button onclick="switchTab('knowledge')" id="nav-knowledge" class="tab-btn active w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition text-amber-400 bg-amber-500/10 border border-amber-500/20">
                        <i data-lucide="book-open" class="w-4 h-4"></i>
                        <span>Cành Tri Thức Vĩnh Viễn</span>
                    </button>
                    <button onclick="switchTab('studio')" id="nav-studio" class="tab-btn w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition text-slate-400 hover:text-slate-200 hover:bg-slate-900">
                        <i data-lucide="headphones" class="w-4 h-4"></i>
                        <span>Audiophile Studio 3D</span>
                    </button>
                    <button onclick="switchTab('companion')" id="nav-companion" class="tab-btn w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition text-slate-400 hover:text-slate-200 hover:bg-slate-900">
                        <i data-lucide="message-square-heart" class="w-4 h-4"></i>
                        <span>Gương Tri Kỷ (Gemini)</span>
                    </button>
                </nav>
            </div>

            <div class="p-3 rounded-xl glass-card text-xs text-slate-400 space-y-2">
                <div class="flex items-center justify-between text-slate-300 font-medium">
                    <span>Trạng thái kiến trúc</span>
                    <span class="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-400 border border-amber-500/30">v7.5.0</span>
                </div>
                <p class="text-[11px] text-slate-500 leading-relaxed">Monolith Cine AI - Tự động trích xuất ngữ cảnh & Đồng bộ hóa không gian âm thanh.</p>
            </div>
        </aside>

        <!-- BACKDROP FOR MOBILE SIDEBAR -->
        <div id="sidebar-backdrop" class="fixed inset-0 bg-black/60 z-40 hidden md:hidden"></div>

        <!-- VIEW CONTENT PANELS -->
        <main class="flex-1 h-full overflow-y-auto scrollbar-none p-4 sm:p-6 lg:p-8 bg-slate-950/50">
            
            <!-- TAB 1: SOUL KNOWLEDGE BRANCH -->
            <section id="tab-knowledge" class="tab-content space-y-6 max-w-5xl mx-auto">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
                    <div>
                        <h1 class="text-xl sm:text-2xl font-serif font-bold text-amber-400">Soul Knowledge Branch</h1>
                        <p class="text-xs sm:text-sm text-slate-400">Két lưu trữ vĩnh viễn các bản thảo, thơ ca và triết lý sáng tạo.</p>
                    </div>
                    <button onclick="openCreateKnowledgeModal()" class="px-4 py-2 bg-amber-500 hover:bg-amber-600 text-slate-950 font-semibold text-xs sm:text-sm rounded-xl shadow-lg transition flex items-center justify-center space-x-2">
                        <i data-lucide="plus-circle" class="w-4 h-4"></i>
                        <span>Lưu Bản Thảo Mới</span>
                    </button>
                </div>

                <!-- SEARCH & FILTER BAR -->
                <div class="flex flex-col sm:flex-row gap-3">
                    <div class="relative flex-1">
                        <i data-lucide="search" class="w-4 h-4 absolute left-3.5 top-3 text-slate-500"></i>
                        <input id="search-knowledge" oninput="debounceSearch()" type="text" placeholder="Tìm kiếm ngữ cảnh, tiêu đề, thẻ tag..." class="w-full pl-10 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 focus:outline-none focus:border-amber-500/50">
                    </div>
                    <select id="filter-category" onchange="loadKnowledge()" class="px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-300 focus:outline-none focus:border-amber-500/50">
                        <option value="All">Tất cả danh mục</option>
                        <option value="Manuscript">Bản Thảo (Manuscript)</option>
                        <option value="Poetry">Thơ Ca (Poetry)</option>
                        <option value="Philosophy">Triết Lý (Philosophy)</option>
                    </select>
                </div>

                <!-- KNOWLEDGE CARDS GRID -->
                <div id="knowledge-list" class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <!-- Dynamic items will be rendered here -->
                </div>
            </section>

            <!-- TAB 2: AUDIOPHILE RESONANCE STUDIO -->
            <section id="tab-studio" class="tab-content hidden space-y-6 max-w-4xl mx-auto">
                <div class="border-b border-slate-800 pb-5">
                    <h1 class="text-xl sm:text-2xl font-serif font-bold text-amber-400">Audiophile Resonance Studio</h1>
                    <p class="text-xs sm:text-sm text-slate-400">Không gian âm thanh tĩnh lặng 3D Binaural Waves hỗ trợ tập trung và lắng đọng tâm hồn.</p>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <!-- AUDIO CONTROLLER PANEL -->
                    <div class="lg:col-span-2 glass-card p-6 rounded-2xl space-y-6 border border-amber-500/20">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center space-x-3">
                                <div class="p-3 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                    <i data-lucide="radio" class="w-6 h-6 animate-pulse"></i>
                                </div>
                                <div>
                                    <h3 class="font-medium text-slate-200 text-sm">Binaural Soundscape Generator</h3>
                                    <p class="text-xs text-slate-400">Web Audio Synthesis Realtime</p>
                                </div>
                            </div>
                            <button id="play-audio-btn" onclick="toggleAudio()" class="px-5 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-600 text-slate-950 font-bold text-xs flex items-center space-x-2 shadow-lg transition">
                                <i id="play-icon" data-lucide="play" class="w-4 h-4"></i>
                                <span id="play-text">Bật Âm Thanh</span>
                            </button>
                        </div>

                        <!-- CONTROLS -->
                        <div class="space-y-4 pt-2">
                            <div>
                                <div class="flex justify-between text-xs mb-1.5">
                                    <span class="text-slate-400">Chế độ Binaural Wave</span>
                                    <span id="wave-type-label" class="text-amber-400 font-mono">Alpha (10 Hz) - Sáng Tạo</span>
                                </div>
                                <div class="grid grid-cols-4 gap-2">
                                    <button onclick="setWavePreset('delta')" class="wave-preset-btn px-2 py-2 rounded-lg text-xs bg-slate-900 border border-slate-800 text-slate-300 hover:border-amber-500/40">Delta (2Hz)</button>
                                    <button onclick="setWavePreset('theta')" class="wave-preset-btn px-2 py-2 rounded-lg text-xs bg-slate-900 border border-slate-800 text-slate-300 hover:border-amber-500/40">Theta (6Hz)</button>
                                    <button onclick="setWavePreset('alpha')" class="wave-preset-btn active px-2 py-2 rounded-lg text-xs bg-amber-500/20 border border-amber-500/40 text-amber-400">Alpha (10Hz)</button>
                                    <button onclick="setWavePreset('gamma')" class="wave-preset-btn px-2 py-2 rounded-lg text-xs bg-slate-900 border border-slate-800 text-slate-300 hover:border-amber-500/40">Gamma (40Hz)</button>
                                </div>
                            </div>

                            <div>
                                <div class="flex justify-between text-xs mb-1.5">
                                    <span class="text-slate-400">Tần số sóng gốc (Carrier Frequency)</span>
                                    <span id="carrier-freq-val" class="text-amber-400 font-mono">216 Hz</span>
                                </div>
                                <input id="carrier-freq" type="range" min="100" max="440" value="216" oninput="updateAudioSettings()" class="w-full accent-amber-400 bg-slate-800 rounded-lg h-1.5 cursor-pointer">
                            </div>

                            <div>
                                <div class="flex justify-between text-xs mb-1.5">
                                    <span class="text-slate-400">Tiếng Mưa Tĩnh Lặng (Ambient Nature Noise)</span>
                                    <span id="ambient-vol-val" class="text-amber-400 font-mono">30%</span>
                                </div>
                                <input id="ambient-vol" type="range" min="0" max="100" value="30" oninput="updateAudioSettings()" class="w-full accent-amber-400 bg-slate-800 rounded-lg h-1.5 cursor-pointer">
                            </div>
                        </div>
                    </div>

                    <!-- 3D PANNER VISUALIZER -->
                    <div class="glass-card p-6 rounded-2xl flex flex-col items-center justify-center space-y-4 text-center border border-slate-800">
                        <div class="w-32 h-32 rounded-full border-2 border-dashed border-amber-500/30 flex items-center justify-center relative animate-spin-slow">
                            <div class="w-20 h-20 rounded-full bg-amber-500/10 border border-amber-400/30 flex items-center justify-center text-amber-400">
                                <i data-lucide="disc" class="w-8 h-8"></i>
                            </div>
                        </div>
                        <div>
                            <h4 class="text-sm font-semibold text-slate-200">3D Spatial Sound Context</h4>
                            <p class="text-xs text-slate-400 mt-1">Hãy đeo tai nghe Stereo để cảm nhận không gian xoay chiều tĩnh lặng.</p>
                        </div>
                    </div>
                </div>
            </section>

            <!-- TAB 3: THE CREATIVE COMPANION MIRROR -->
            <section id="tab-companion" class="tab-content hidden flex flex-col h-full max-w-4xl mx-auto space-y-4">
                <div class="border-b border-slate-800 pb-4 flex justify-between items-center">
                    <div>
                        <h1 class="text-xl font-serif font-bold text-amber-400">The Creative Companion Mirror</h1>
                        <p class="text-xs text-slate-400">Góc đối thoại tri kỷ qua Streaming SSE kết nối Gemini.</p>
                    </div>
                    <input id="gemini-api-key" type="password" placeholder="Gắn Gemini API Key (Tùy chọn)" class="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-amber-500/50 w-48 sm:w-64">
                </div>

                <!-- CHAT MESSAGES BOX -->
                <div id="chat-container" class="flex-1 overflow-y-auto space-y-4 p-4 rounded-2xl glass-card border border-slate-800 min-h-[350px] max-h-[50vh] scrollbar-none">
                    <div class="flex items-start space-x-3">
                        <div class="w-8 h-8 rounded-full bg-amber-500/20 border border-amber-400/40 flex items-center justify-center text-amber-400 shrink-0">
                            <i data-lucide="sparkles" class="w-4 h-4"></i>
                        </div>
                        <div class="bg-slate-900 border border-slate-800 p-3.5 rounded-2xl rounded-tl-none max-w-[85%] text-xs sm:text-sm text-slate-300 leading-relaxed">
                            Xin chào. Tôi là Tri Kỷ Cộng Hưởng. Hãy chia sẻ bất kỳ cảm xúc thô, suy tư chưa trọn vẹn hay dòng suy nghĩ mộc mạc nào... Tôi sẵn sàng lắng nghe và cùng bạn chuyển hóa chúng.
                        </div>
                    </div>
                </div>

                <!-- CHAT INPUT AREA -->
                <form id="chat-form" onsubmit="sendCompanionMessage(event)" class="flex items-center space-x-2">
                    <input id="chat-input" type="text" placeholder="Nói với Tri Kỷ tâm sự của bạn..." required class="flex-1 px-4 py-3 bg-slate-900 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 focus:outline-none focus:border-amber-500/50">
                    <button type="submit" id="send-btn" class="px-4 py-3 bg-amber-500 hover:bg-amber-600 text-slate-950 font-bold rounded-xl shadow-lg transition flex items-center justify-center">
                        <i data-lucide="send" class="w-4 h-4"></i>
                    </button>
                </form>
            </section>

        </main>
    </div>

    <!-- MODAL: KNOWLEDGE CREATION -->
    <div id="modal-knowledge" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="glass-card border border-amber-500/30 rounded-2xl p-6 w-full max-w-lg space-y-4 shadow-2xl">
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <h3 class="text-base font-bold text-amber-400 font-serif">Lưu Bản Thảo / Triết Lý Mới</h3>
                <button onclick="closeModal('modal-knowledge')" class="text-slate-400 hover:text-slate-200"><i data-lucide="x" class="w-5 h-5"></i></button>
            </div>
            <form onsubmit="saveKnowledge(event)" class="space-y-4">
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Tiêu đề bản ghi</label>
                    <input id="k-title" type="text" required placeholder="Nhập tiêu đề tác phẩm..." class="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 focus:outline-none focus:border-amber-500/50">
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Phân loại</label>
                    <select id="k-category" class="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 focus:outline-none focus:border-amber-500/50">
                        <option value="Manuscript">Bản Thảo (Manuscript)</option>
                        <option value="Poetry">Thơ Ca (Poetry)</option>
                        <option value="Philosophy">Triết Lý Sáng Tạo (Philosophy)</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Thẻ tùy chọn (cách nhau bởi dấu phẩy)</label>
                    <input id="k-tags" type="text" placeholder="ví dụ: tĩnh lặng, ký ức, không gian" class="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 focus:outline-none focus:border-amber-500/50">
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Nội dung tác phẩm</label>
                    <textarea id="k-content" rows="5" required placeholder="Viết những dòng sáng tạo của bạn tại đây..." class="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 focus:outline-none focus:border-amber-500/50 resize-none"></textarea>
                </div>
                <div class="flex justify-end space-x-2 pt-2">
                    <button type="button" onclick="closeModal('modal-knowledge')" class="px-4 py-2 rounded-xl text-xs text-slate-400 hover:bg-slate-900">Hủy</button>
                    <button type="submit" class="px-4 py-2 rounded-xl text-xs font-bold bg-amber-500 hover:bg-amber-600 text-slate-950">Lưu Vĩnh Viễn</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL: AUTHENTICATION -->
    <div id="modal-auth" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="glass-card border border-amber-500/30 rounded-2xl p-6 w-full max-w-sm space-y-4 shadow-2xl">
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <h3 id="auth-title" class="text-base font-bold text-amber-400 font-serif">Đăng Nhập Sanctuary</h3>
                <button onclick="closeModal('modal-auth')" class="text-slate-400 hover:text-slate-200"><i data-lucide="x" class="w-5 h-5"></i></button>
            </div>
            <form onsubmit="handleAuth(event)" class="space-y-4">
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Tên tài khoản</label>
                    <input id="auth-username" type="text" required class="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-amber-500/50">
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Mật khẩu</label>
                    <input id="auth-password" type="password" required class="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-amber-500/50">
                </div>
                <div class="pt-2 space-y-2">
                    <button type="submit" id="auth-submit-btn" class="w-full py-2.5 rounded-xl text-xs font-bold bg-amber-500 hover:bg-amber-600 text-slate-950 shadow-lg transition">Đăng Nhập</button>
                    <button type="button" onclick="toggleAuthMode()" id="auth-toggle-btn" class="w-full text-center text-xs text-amber-400/80 hover:underline">Chưa có tài khoản? Đăng ký ngay</button>
                </div>
            </form>
        </div>
    </div>

    <!-- JAVASCRIPT LOGIC -->
    <script>
        let currentUser = {user_json};
        let isRegisterMode = false;
        let searchTimeout = null;

        // WEB AUDIO API ENGINE
        let audioCtx = null;
        let leftOsc = null, rightOsc = null;
        let noiseNode = null;
        let isPlaying = false;
        let currentBeatFreq = 10; // Alpha default

        document.addEventListener('DOMContentLoaded', () => {{
            lucide.createIcons();
            setupDrawer();
            updateAuthUI();
            if (currentUser) loadKnowledge();
        }});

        function setupDrawer() {{
            const menuBtn = document.getElementById('menu-btn');
            const closeBtn = document.getElementById('close-sidebar');
            const sidebar = document.getElementById('sidebar');
            const backdrop = document.getElementById('sidebar-backdrop');

            function toggle() {{
                sidebar.classList.toggle('-translate-x-full');
                backdrop.classList.toggle('hidden');
            }}
            menuBtn.addEventListener('click', toggle);
            closeBtn.addEventListener('click', toggle);
            backdrop.addEventListener('click', toggle);
        }}

        function switchTab(tabId) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(el => {{
                el.classList.remove('text-amber-400', 'bg-amber-500/10', 'border', 'border-amber-500/20');
                el.classList.add('text-slate-400');
            }});

            document.getElementById(`tab-${{tabId}}`).classList.remove('hidden');
            const activeNav = document.getElementById(`nav-${{tabId}}`);
            activeNav.classList.add('text-amber-400', 'bg-amber-500/10', 'border', 'border-amber-500/20');
            activeNav.classList.remove('text-slate-400');
            
            if (window.innerWidth < 768) {{
                document.getElementById('sidebar').classList.add('-translate-x-full');
                document.getElementById('sidebar-backdrop').classList.add('hidden');
            }}
        }}

        // AUTHENTICATION SYSTEM
        function updateAuthUI() {{
            if (currentUser) {{
                document.getElementById('auth-user-info').classList.remove('hidden');
                document.getElementById('auth-user-info').classList.add('flex');
                document.getElementById('auth-guest-info').classList.add('hidden');
                document.getElementById('user-display-name').innerText = currentUser.username;
            }} else {{
                document.getElementById('auth-user-info').classList.add('hidden');
                document.getElementById('auth-guest-info').classList.remove('hidden');
            }}
        }}

        function openAuthModal() {{
            document.getElementById('modal-auth').classList.remove('hidden');
        }}

        function closeModal(id) {{
            document.getElementById(id).classList.add('hidden');
        }}

        function toggleAuthMode() {{
            isRegisterMode = !isRegisterMode;
            document.getElementById('auth-title').innerText = isRegisterMode ? 'Đăng Ký Sanctuary' : 'Đăng Nhập Sanctuary';
            document.getElementById('auth-submit-btn').innerText = isRegisterMode ? 'Đăng Ký' : 'Đăng Nhập';
            document.getElementById('auth-toggle-btn').innerText = isRegisterMode ? 'Đã có tài khoản? Đăng nhập' : 'Chưa có tài khoản? Đăng ký ngay';
        }}

        async function handleAuth(e) {{
            e.preventDefault();
            const username = document.getElementById('auth-username').value;
            const password = document.getElementById('auth-password').value;
            const endpoint = isRegisterMode ? '/api/auth/register' : '/api/auth/login';

            try {{
                const res = await fetch(endpoint, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ username, password }})
                }});
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Lỗi xác thực');
                
                if (isRegisterMode) {{
                    alert('Đăng ký thành công! Hãy đăng nhập.');
                    toggleAuthMode();
                }} else {{
                    location.reload();
                }}
            }} catch (err) {{
                alert(err.message);
            }}
        }}

        async function logout() {{
            await fetch('/api/auth/logout', {{ method: 'POST' }});
            location.reload();
        }}

        // KNOWLEDGE BRANCH SYSTEM
        function openCreateKnowledgeModal() {{
            if (!currentUser) return openAuthModal();
            document.getElementById('modal-knowledge').classList.remove('hidden');
        }}

        function debounceSearch() {{
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(loadKnowledge, 300);
        }}

        async function loadKnowledge() {{
            if (!currentUser) {{
                document.getElementById('knowledge-list').innerHTML = `
                    <div class="col-span-full text-center py-12 border border-dashed border-slate-800 rounded-2xl p-6">
                        <p class="text-slate-400 text-sm mb-3">Vui lòng đăng nhập để truy cập Cành Tri Thức Vĩnh Viễn của bạn.</p>
                        <button onclick="openAuthModal()" class="px-4 py-2 bg-amber-500 text-slate-950 font-bold text-xs rounded-xl">Đăng Nhập Ngay</button>
                    </div>`;
                return;
            }}
            const cat = document.getElementById('filter-category').value;
            const search = document.getElementById('search-knowledge').value;
            const url = `/api/knowledge?category=${{encodeURIComponent(cat)}}&search=${{encodeURIComponent(search)}}`;
            
            try {{
                const res = await fetch(url);
                const items = await res.json();
                const container = document.getElementById('knowledge-list');
                
                if (items.length === 0) {{
                    container.innerHTML = `<div class="col-span-full text-center py-12 text-slate-500 text-xs">Chưa có ghi chép nào trong kho ký ức.</div>`;
                    return;
                }}

                container.innerHTML = items.map(item => `
                    <div class="glass-card p-5 rounded-2xl flex flex-col justify-between space-y-3 border border-slate-800 hover:border-amber-500/30 transition">
                        <div>
                            <div class="flex justify-between items-start mb-2">
                                <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">${{item.category}}</span>
                                <button onclick="deleteKnowledge(${{item.id}})" class="text-slate-500 hover:text-red-400 transition"><i data-lucide="trash-2" class="w-3.5 h-3.5"></i></button>
                            </div>
                            <h3 class="font-serif font-bold text-slate-200 text-base mb-1.5">${{item.title}}</h3>
                            <p class="text-xs text-slate-400 leading-relaxed whitespace-pre-line">${{item.content}}</p>
                        </div>
                        <div class="pt-2 border-t border-slate-800/60 flex flex-wrap gap-1.5 items-center justify-between">
                            <div class="flex flex-wrap gap-1">
                                ${{item.tags.map(t => `<span class="text-[10px] text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">#${{t}}</span>`).join('')}}
                            </div>
                            <span class="text-[10px] text-slate-500 font-mono">${{new Date(item.created_at).toLocaleDateString('vi-VN')}}</span>
                        </div>
                    </div>
                `).join('');
                lucide.createIcons();
            }} catch (err) {{
                console.error(err);
            }}
        }}

        async function saveKnowledge(e) {{
            e.preventDefault();
            const title = document.getElementById('k-title').value;
            const category = document.getElementById('k-category').value;
            const custom_tags = document.getElementById('k-tags').value;
            const content = document.getElementById('k-content').value;

            try {{
                const res = await fetch('/api/knowledge', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ title, category, custom_tags, content }})
                }});
                if (res.ok) {{
                    closeModal('modal-knowledge');
                    document.getElementById('k-title').value = '';
                    document.getElementById('k-content').value = '';
                    loadKnowledge();
                }}
            }} catch (err) {{
                alert('Lỗi khi lưu bản thảo');
            }}
        }}

        async function deleteKnowledge(id) {{
            if (!confirm('Bạn có chắc chắn muốn xóa ghi chép này khỏi kho ký ức?')) return;
            await fetch(`/api/knowledge/${{id}}`, {{ method: 'DELETE' }});
            loadKnowledge();
        }}

        // AUDIOPHILE BINAURAL SOUND ENGINE (WEB AUDIO API)
        function toggleAudio() {{
            if (isPlaying) {{
                stopAudio();
            }} else {{
                startAudio();
            }}
        }}

        function startAudio() {{
            if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            if (audioCtx.state === 'suspended') audioCtx.resume();

            const carrier = parseFloat(document.getElementById('carrier-freq').value);
            
            // Left Ear Channel (Carrier)
            leftOsc = audioCtx.createOscillator();
            const leftMerger = audioCtx.createChannelMerger(2);
            leftOsc.frequency.value = carrier;
            leftOsc.connect(leftMerger, 0, 0);
            leftMerger.connect(audioCtx.destination);

            // Right Ear Channel (Carrier + Beat)
            rightOsc = audioCtx.createOscillator();
            const rightMerger = audioCtx.createChannelMerger(2);
            rightOsc.frequency.value = carrier + currentBeatFreq;
            rightOsc.connect(rightMerger, 0, 1);
            rightMerger.connect(audioCtx.destination);

            leftOsc.start();
            rightOsc.start();
            isPlaying = true;

            document.getElementById('play-icon').setAttribute('data-lucide', 'square');
            document.getElementById('play-text').innerText = 'Tắt Âm Thanh';
            lucide.createIcons();
        }}

        function stopAudio() {{
            if (leftOsc) {{ leftOsc.stop(); leftOsc.disconnect(); }}
            if (rightOsc) {{ rightOsc.stop(); rightOsc.disconnect(); }}
            isPlaying = false;
            document.getElementById('play-icon').setAttribute('data-lucide', 'play');
            document.getElementById('play-text').innerText = 'Bật Âm Thanh';
            lucide.createIcons();
        }}

        function setWavePreset(type) {{
            document.querySelectorAll('.wave-preset-btn').forEach(b => b.classList.remove('active', 'bg-amber-500/20', 'border-amber-500/40', 'text-amber-400'));
            event.target.classList.add('active', 'bg-amber-500/20', 'border-amber-500/40', 'text-amber-400');
            
            const presets = {{ 'delta': 2, 'theta': 6, 'alpha': 10, 'gamma': 40 }};
            const labels = {{
                'delta': 'Delta (2 Hz) - Tĩnh Lặng Trầm',
                'theta': 'Theta (6 Hz) - Thiền Định',
                'alpha': 'Alpha (10 Hz) - Sáng Tạo',
                'gamma': 'Gamma (40 Hz) - Tập Trung Cao'
            }};
            currentBeatFreq = presets[type];
            document.getElementById('wave-type-label').innerText = labels[type];
            updateAudioSettings();
        }}

        function updateAudioSettings() {{
            const carrier = parseFloat(document.getElementById('carrier-freq').value);
            document.getElementById('carrier-freq-val').innerText = `${{carrier}} Hz`;
            document.getElementById('ambient-vol-val').innerText = `${{document.getElementById('ambient-vol').value}}%`;
            
            if (isPlaying) {{
                leftOsc.frequency.setTargetAtTime(carrier, audioCtx.currentTime, 0.1);
                rightOsc.frequency.setTargetAtTime(carrier + currentBeatFreq, audioCtx.currentTime, 0.1);
            }}
        }}

        // COMPANION GEMINI SSE STREAMING
        async function sendCompanionMessage(e) {{
            e.preventDefault();
            if (!currentUser) return openAuthModal();
            
            const input = document.getElementById('chat-input');
            const msg = input.value.trim();
            if (!msg) return;
            
            const apiKey = document.getElementById('gemini-api-key').value;
            const chatContainer = document.getElementById('chat-container');
            
            // Append User Message
            chatContainer.innerHTML += `
                <div class="flex items-start space-x-3 justify-end">
                    <div class="bg-amber-500/10 border border-amber-500/30 p-3.5 rounded-2xl rounded-tr-none max-w-[85%] text-xs sm:text-sm text-amber-200 leading-relaxed">
                        ${{msg}}
                    </div>
                </div>`;
            input.value = '';
            chatContainer.scrollTop = chatContainer.scrollHeight;

            // Append Bot Placeholder
            const botMsgId = 'bot-msg-' + Date.now();
            chatContainer.innerHTML += `
                <div class="flex items-start space-x-3">
                    <div class="w-8 h-8 rounded-full bg-amber-500/20 border border-amber-400/40 flex items-center justify-center text-amber-400 shrink-0">
                        <i data-lucide="sparkles" class="w-4 h-4"></i>
                    </div>
                    <div id="${{botMsgId}}" class="bg-slate-900 border border-slate-800 p-3.5 rounded-2xl rounded-tl-none max-w-[85%] text-xs sm:text-sm text-slate-300 leading-relaxed whitespace-pre-line">
                        <span class="animate-pulse text-amber-400/70">Đang lắng nghe và suy ngẫm...</span>
                    </div>
                </div>`;
            lucide.createIcons();
            chatContainer.scrollTop = chatContainer.scrollHeight;

            try {{
                const response = await fetch('/api/companion/stream', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ message: msg, api_key: apiKey }})
                }});

                const reader = response.body.getReader();
                const decoder = new TextDecoder('utf-8');
                const botMsgEl = document.getElementById(botMsgId);
                botMsgEl.innerHTML = '';

                while (true) {{
                    const {{ done, value }} = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value, {{ stream: true }});
                    const lines = chunk.split('\n');
                    
                    for (const line of lines) {{
                        if (line.startsWith('data: ')) {{
                            const dataStr = line.replace('data: ', '').trim();
                            if (dataStr === '[DONE]') break;
                            try {{
                                const parsed = JSON.parse(dataStr);
                                if (parsed.text) {{
                                    botMsgEl.innerHTML += parsed.text;
                                    chatContainer.scrollTop = chatContainer.scrollHeight;
                                }}
                            }} catch (e) {{}}
                        }}
                    }}
                }}
            }} catch (err) {{
                document.getElementById(botMsgId).innerText = 'Đã có lỗi kết nối. Vui lòng thử lại.';
            }}
        }}
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)

# ========================================== #
# APPLICATION ENTRYPOINT                     #
# ========================================== #

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

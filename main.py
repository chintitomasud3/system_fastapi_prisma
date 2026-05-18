from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from datetime import timedelta
import uvicorn
from contextlib import asynccontextmanager
from pydantic import BaseModel
import psutil
import platform

from auth import (
    prisma,
    get_password_hash,
    verify_password,
    create_access_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    get_current_user,
    get_admin_user
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Connect to the database on startup
    if not prisma.is_connected():
        await prisma.connect()
    
    # Create a default admin user if none exists
    admin = await prisma.user.find_first(where={"role": "ADMIN"})
    if not admin:
        await prisma.user.create(data={
            "name": "Admin",
            "age": 30,
            "city": "AdminCity",
            "email": "admin@example.com",
            "password": get_password_hash("admin123"),
            "role": "ADMIN"
        })
    yield
    # Disconnect on shutdown
    if prisma.is_connected():
        await prisma.disconnect()

app = FastAPI(lifespan=lifespan)

# Allow CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserCreate(BaseModel):
    name: str
    age: int
    city: str
    email: str
    password: str

class PostCreate(BaseModel):
    title: str
    content: str

@app.post("/register")
async def register(user: UserCreate):
    existing_user = await prisma.user.find_first(where={"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = await prisma.user.create(
        data={
            "name": user.name,
            "age": user.age,
            "city": user.city,
            "email": user.email,
            "password": get_password_hash(user.password),
            "role": "USER"
        }
    )
    return {"msg": "User created successfully", "id": new_user.id}

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Here username is used as email
    user = await prisma.user.find_first(where={"email": form_data.username})
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "role": user.role, "name": user.name}

@app.get("/users/me")
async def read_users_me(current_user = Depends(get_current_user)):
    return current_user

@app.post("/posts")
async def create_post(post: PostCreate, current_user = Depends(get_current_user)):
    try:
        new_post = await prisma.post.create(
            data={
                "title": post.title,
                "content": post.content,
                "authorId": current_user.id
            }
        )
        return new_post
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create post: {str(e)}")

@app.get("/posts")
async def get_all_posts():
    try:
        posts = await prisma.post.find_many(include={"author": True, "comments": True})
        return posts
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch posts: {str(e)}")

# --- ADMIN ROUTES ---

@app.get("/admin/stats")
async def get_admin_stats(current_user = Depends(get_admin_user)):
    users_count = await prisma.user.count()
    posts_count = await prisma.post.count()
    comments_count = await prisma.comment.count()
    return {
        "users": users_count,
        "posts": posts_count,
        "comments": comments_count
    }

@app.get("/admin/users")
async def get_admin_users(current_user = Depends(get_admin_user)):
    users = await prisma.user.find_many(include={"posts": True})
    return users

@app.get("/admin/posts")
async def get_admin_posts(current_user = Depends(get_admin_user)):
    posts = await prisma.post.find_many(include={"author": True, "comments": True})
    return posts

@app.get("/admin/system/info")
async def get_system_info(current_user = Depends(get_admin_user)):
    try:
        # CPU Info (non-blocking)
        cpu_percent = psutil.cpu_percent(interval=None)
        cpu_logical = psutil.cpu_count(logical=True)
        cpu_physical = psutil.cpu_count(logical=False)
        
        # Memory Info
        virtual_mem = psutil.virtual_memory()
        total_mem = round(virtual_mem.total / (1024 ** 3), 1)
        used_mem = round(virtual_mem.used / (1024 ** 3), 1)
        available_mem = round(virtual_mem.available / (1024 ** 3), 1)
        memory_percent = virtual_mem.percent
        
        # Disk Info (Main drive)
        disk_usage = psutil.disk_usage('/')
        total_disk = round(disk_usage.total / (1024 ** 3), 1)
        used_disk = round(disk_usage.used / (1024 ** 3), 1)
        free_disk = round(disk_usage.free / (1024 ** 3), 1)
        disk_percent = disk_usage.percent
        
        # Platform Info
        os_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor()
        }
        
        return {
            "cpu": {
                "percent": cpu_percent,
                "logical_cores": cpu_logical,
                "physical_cores": cpu_physical
            },
            "memory": {
                "total_gb": total_mem,
                "used_gb": used_mem,
                "available_gb": available_mem,
                "percent": memory_percent
            },
            "disk": {
                "total_gb": total_disk,
                "used_gb": used_disk,
                "free_gb": free_disk,
                "percent": disk_percent
            },
            "os": os_info
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch system info: {str(e)}")

@app.get("/admin/processes")
async def get_admin_processes(current_user = Depends(get_admin_user)):
    try:
        processes = []
        for proc in psutil.process_iter():
            try:
                # Optimized single system-call cache
                with proc.oneshot():
                    pid = proc.pid
                    try:
                        name = proc.name()
                    except psutil.AccessDenied:
                        name = "Access Denied"
                    
                    try:
                        username = proc.username()
                    except psutil.AccessDenied:
                        username = "Access Denied"
                    
                    try:
                        cpu = proc.cpu_percent()
                    except psutil.AccessDenied:
                        cpu = 0.0
                        
                    try:
                        memory = proc.memory_percent()
                    except psutil.AccessDenied:
                        memory = 0.0

                processes.append({
                    "pid": pid,
                    "name": name or "Unknown",
                    "username": username or "System",
                    "cpu": round(cpu or 0.0, 1),
                    "memory": round(memory or 0.0, 1)
                })
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
        
        # Sort by memory usage descending and take the top 50
        processes = sorted(processes, key=lambda x: x['memory'], reverse=True)[:50]
        return processes
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch processes: {str(e)}")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8005, reload=True)

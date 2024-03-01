from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime
from typing import List
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import pytz
from jinja2 import Environment, FileSystemLoader

app = FastAPI()

env = Environment(
    loader=FileSystemLoader('./'),
)

status_data = {}

class StatusItem(BaseModel):
    IP: str
    Host: str
    Message: str

class StatusResponse(BaseModel):
    IP: str
    Host: str
    Message: str
    Time: str

@app.post("/status")
async def post_status(item: StatusItem):
    now = datetime.now(pytz.timezone('Europe/Berlin'))
    status_data[item.IP] = {"Host": item.Host, "Message": item.Message, "Time": now}
    return []

@app.get("/status", response_model=List[StatusResponse])
async def get_status():
    return [
        {"IP": ip, "Host": data["Host"], "Message": data["Message"], "Time": data["Time"].strftime("%Y-%m-%d %H:%M:%S")}
        for ip, data in status_data.items()
    ]

@app.get("/", response_class=HTMLResponse)
async def show_status():
    sorted_status = sorted(status_data.items(), key=lambda x: x[1]["Time"], reverse=True)
    template = env.get_template('status.html')
    return template.render({"request": None, "status": sorted_status})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

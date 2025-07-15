from fastapi import FastAPI, Request
from pydantic import BaseModel
from transformers import nmap_to_unified
import uuid
import docker

app = FastAPI()

class ScanRequest(BaseModel):
    target: str

@app.post("/scans")
def start_scan(scan_req: ScanRequest):
    scan_id = str(uuid.uuid4())
    target = scan_req.target

    try:
        client = docker.from_env()
        command = f"nmap -Pn -p 80 {target}"
        out = client.containers.run(
            image="instrumentisto/nmap",
            command=command,
            remove=True,
            stdout=True,
            stderr=True
        )
        raw_output = out.decode()
        unified = nmap_to_unified(raw_output, scan_id, target)
        return unified
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

@app.get("/healthz")
def health_check():
    return {"status": "ok"}

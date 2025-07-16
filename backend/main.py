import threading
import queue
import time
from fastapi import FastAPI
from pydantic import BaseModel
import uuid
from transformers import nmap_to_unified
import docker
from utils import send_to_splunk
from fastapi.middleware.cors import CORSMiddleware


# Maximum number of scans that can run at the same time
MAX_CONCURRENT_SCANS = 2

# Shared objects to track scan jobs and results
scan_job_queue = queue.Queue()
scan_results = {}      # Maps scan_id to result dict
scan_status = {}       # Maps scan_id to status: 'queued', 'running', 'done', 'error'

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React dev server origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str

def scan_worker():
    while True:
        scan_id, target = scan_job_queue.get()
        try:
            scan_status[scan_id] = 'running'
            print(f"Running Nmap scan for {target} (scan_id={scan_id})...")
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
            print("Nmap scan finished, now parsing output...")
            unified = nmap_to_unified(raw_output, scan_id, target)
            scan_results[scan_id] = unified
            scan_status[scan_id] = 'done'
            print("Sending results to Splunk...")
            code, resp = send_to_splunk(unified)
            print(f"Splunk response: {code} {resp}")
        except Exception as e:
            scan_results[scan_id] = {'error': str(e)}
            scan_status[scan_id] = 'error'
        finally:
            scan_job_queue.task_done()


# Start worker threads (will keep running in the background)
for _ in range(MAX_CONCURRENT_SCANS):
    t = threading.Thread(target=scan_worker, daemon=True)
    t.start()

@app.post("/scans")
def start_scan(scan_req: ScanRequest):
    """
    Submits a new scan request.
    Returns a scan_id and status message.
    The actual scan will be picked up by the worker as soon as possible.
    """
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = None
    scan_status[scan_id] = 'queued'
    scan_job_queue.put((scan_id, scan_req.target))
    return {
        "scan_id": scan_id,
        "status": scan_status[scan_id],
        "message": "Scan submitted and queued. Use /scans/{scan_id} to check status and result."
    }

@app.get("/scans/{scan_id}")
def get_scan_status(scan_id: str):
    """
    Returns the current status and (if done) the result of the scan.
    """
    status = scan_status.get(scan_id)
    result = scan_results.get(scan_id)
    if status is None:
        return {"error": "Scan ID not found"}
    return {
        "scan_id": scan_id,
        "status": status,
        "result": result
    }

@app.get("/healthz")
def health_check():
    """
    Simple health check for Docker Compose.
    """
    return {"status": "ok"}

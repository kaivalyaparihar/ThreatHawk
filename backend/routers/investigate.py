#backend\routers\investigate.py

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database import get_db
from utils.ioc_type_detector import detect_ioc_type, is_valid_ioc
from engines.ioc_investigator import investigate
import json
import models
from datetime import datetime

router = APIRouter()


class IOCRequest(BaseModel):
    ioc: str


@router.post("/")
async def investigate_ioc(request: IOCRequest, db: Session = Depends(get_db)):
    ioc = request.ioc.strip()

    # Validate IOC
    if not is_valid_ioc(ioc):
        raise HTTPException(status_code=400, detail=f"Unrecognised IOC format: {ioc}")

    ioc_type = detect_ioc_type(ioc)

    # Run full multi-source investigation
    result = await investigate(ioc, ioc_type, db)

    return result


@router.get("/history")
def get_history(db: Session = Depends(get_db)):
    records = db.query(models.IOCResult).order_by(
        models.IOCResult.created_at.desc()
    ).limit(50).all()

    return [
        {
            "id": r.id,
            "ioc": r.ioc,
            "ioc_type": r.ioc_type,
            "threat_score": r.threat_score,
            "severity": r.severity,
            "created_at": r.created_at
        }
        for r in records
    ]


@router.get("/{investigation_id}")
def get_investigation(investigation_id: int, db: Session = Depends(get_db)):
    record = db.query(models.IOCResult).filter(
        models.IOCResult.id == investigation_id
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return {
        "id": record.id,
        "ioc": record.ioc,
        "ioc_type": record.ioc_type,
        "threat_score": record.threat_score,
        "severity": record.severity,
        "results": json.loads(record.raw_results) if record.raw_results else {},
        "graph_data": json.loads(record.graph_data) if record.graph_data else {"nodes": [], "edges": []},
        "created_at": record.created_at
    }
#backend\routers\cases.py

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database import get_db
from datetime import datetime, timezone
import json
import models

router = APIRouter()


class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "Medium"


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None


@router.post("/")
def create_case(data: CaseCreate, db: Session = Depends(get_db)):
    case = models.Case(
        title=data.title,
        description=data.description,
        severity=data.severity,
        status="Open",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    return {
        "id": case.id,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "created_at": case.created_at,
    }


@router.get("/")
def get_cases(status: str = None, db: Session = Depends(get_db)):
    query = db.query(models.Case)
    if status:
        query = query.filter(models.Case.status == status)

    cases = query.order_by(models.Case.updated_at.desc()).all()

    return [
        {
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "severity": c.severity,
            "status": c.status,
            "notes": c.notes,
            "created_at": c.created_at,
            "updated_at": c.updated_at,
            "linked_iocs": db.query(models.IOCResult).filter(models.IOCResult.case_id == c.id).count(),
            "linked_victims": db.query(models.DarkWebVictim).filter(models.DarkWebVictim.case_id == c.id).count(),
        }
        for c in cases
    ]


@router.get("/{case_id}")
def get_case(case_id: int, db: Session = Depends(get_db)):
    c = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    linked_iocs = db.query(models.IOCResult).filter(
        models.IOCResult.case_id == case_id
    ).order_by(models.IOCResult.created_at.desc()).all()

    linked_victims = db.query(models.DarkWebVictim).filter(
        models.DarkWebVictim.case_id == case_id
    ).order_by(models.DarkWebVictim.created_at.desc()).all()

    # Build timeline from all linked evidence
    timeline = []
    for ioc in linked_iocs:
        timeline.append({
            "type": "ioc",
            "id": ioc.id,
            "value": ioc.ioc,
            "ioc_type": ioc.ioc_type,
            "severity": ioc.severity,
            "threat_score": ioc.threat_score,
            "date": str(ioc.created_at),
        })
    for v in linked_victims:
        timeline.append({
            "type": "victim",
            "id": v.id,
            "value": v.victim_name,
            "gang": v.gang,
            "severity": "High",
            "date": str(v.created_at),
        })
    timeline.sort(key=lambda x: x["date"], reverse=True)

    return {
        "id": c.id,
        "title": c.title,
        "description": c.description,
        "severity": c.severity,
        "status": c.status,
        "notes": c.notes,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
        "timeline": timeline,
        "linked_iocs_count": len(linked_iocs),
        "linked_victims_count": len(linked_victims),
    }


@router.put("/{case_id}")
def update_case(case_id: int, data: CaseUpdate, db: Session = Depends(get_db)):
    c = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    if data.title is not None:
        c.title = data.title
    if data.description is not None:
        c.description = data.description
    if data.notes is not None:
        c.notes = data.notes
    if data.status is not None:
        c.status = data.status
    if data.severity is not None:
        c.severity = data.severity

    c.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(c)

    return {"id": c.id, "title": c.title, "status": c.status, "updated_at": c.updated_at}


@router.delete("/{case_id}")
def delete_case(case_id: int, db: Session = Depends(get_db)):
    c = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    db.delete(c)
    db.commit()
    return {"message": "Case deleted"}


@router.post("/{case_id}/link/ioc/{ioc_id}")
def link_ioc(case_id: int, ioc_id: int, db: Session = Depends(get_db)):
    c = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    ioc = db.query(models.IOCResult).filter(models.IOCResult.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC result not found")

    ioc.case_id = case_id
    db.commit()
    return {"message": f"IOC {ioc_id} linked to case {case_id}"}


@router.post("/{case_id}/link/victim/{victim_id}")
def link_victim(case_id: int, victim_id: int, db: Session = Depends(get_db)):
    c = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    victim = db.query(models.DarkWebVictim).filter(models.DarkWebVictim.id == victim_id).first()
    if not victim:
        raise HTTPException(status_code=404, detail="Victim not found")

    victim.case_id = case_id
    db.commit()
    return {"message": f"Victim {victim_id} linked to case {case_id}"}

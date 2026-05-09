#backend\routers\reports.py

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from database import get_db
from utils.report_generator import generate_ioc_report, generate_case_report, generate_darkweb_report
import os
import models

router = APIRouter()

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports_out")


@router.post("/generate/ioc/{investigation_id}")
def gen_ioc_report(investigation_id: int, db: Session = Depends(get_db)):
    try:
        report_id = generate_ioc_report(investigation_id, db)
        return {"message": "Report generated", "report_id": report_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.post("/generate/case/{case_id}")
def gen_case_report(case_id: int, db: Session = Depends(get_db)):
    try:
        report_id = generate_case_report(case_id, db)
        return {"message": "Report generated", "report_id": report_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.post("/generate/darkweb")
def gen_darkweb_report(db: Session = Depends(get_db)):
    try:
        report_id = generate_darkweb_report(db)
        return {"message": "Report generated", "report_id": report_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.get("/")
def list_reports(db: Session = Depends(get_db)):
    reports = db.query(models.Report).order_by(models.Report.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "report_type": r.report_type,
            "file_path": r.file_path,
            "case_id": r.case_id,
            "created_at": r.created_at,
        }
        for r in reports
    ]


@router.get("/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    filepath = os.path.join(REPORTS_DIR, report.file_path)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    return FileResponse(
        filepath,
        media_type="application/pdf",
        filename=report.file_path,
    )

"""
AppSec Vulnerability Triage Interface.

This module provides a Streamlit-based web interface for manually classifying
security findings as either true positives or false positives. It integrates
directly with the OSPO PostgreSQL database via SQLAlchemy.
"""

import os
import sys
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

# Configure application logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def initialize_database() -> Optional[Engine]:
    """
    Initializes and returns the database engine using environment variables.
    Fails securely if connection parameters are missing or invalid.
    """
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        # Fallback for local development, but warns the user.
        logger.warning("DATABASE_URL not set in environment. Using fallback.")
        db_url = "postgresql://myuser:mypassword@localhost:5432/osposervices"

    try:
        engine = create_engine(db_url, pool_pre_ping=True)
        # Assertion of state: Validate connection before proceeding
        with engine.connect() as conn:
            pass
        return engine
    except SQLAlchemyError as e:
        logger.error(f"Database initialization failed: {e}")
        return None

def fetch_unprocessed_finding(engine: Engine) -> pd.DataFrame:
    """
    Retrieves a single unprocessed vulnerability finding from the database.
    
    Args:
        engine: Active SQLAlchemy database engine.
        
    Returns:
        pd.DataFrame: Contains finding data, or is empty if none exist/error occurs.
    """
    assert isinstance(engine, Engine), "Invalid database engine provided."

    query = text("""
        SELECT 
            f.id AS finding_id,
            p.name AS package_name,
            p.version AS package_version,
            p.ecosystem,
            c.id AS cve_id,
            c.score AS cvss_score,
            c.description
        FROM findings f
        JOIN packages p ON f.package_id = p.id
        JOIN cves c ON f.cve_id = c.id
        LEFT JOIN fp_labels fp ON f.id = fp.finding_id
        WHERE fp.id IS NULL
        LIMIT 1;
    """)
    
    try:
        return pd.read_sql(query, engine)
    except SQLAlchemyError as e:
        logger.error(f"Failed to execute fetch_unprocessed_finding query: {e}")
        return pd.DataFrame()

def submit_classification(engine: Engine, finding_id: str, is_false_positive: bool) -> bool:
    """
    Persists the user's classification to the fp_labels table.
    
    Args:
        engine: Active SQLAlchemy database engine.
        finding_id: UUID string of the finding.
        is_false_positive: Boolean representing the classification.
        
    Returns:
        bool: True if successful, False otherwise.
    """
    # Defensive programming: Pre-condition checks
    assert isinstance(finding_id, str) and len(finding_id) > 0, "finding_id must be a valid string"
    assert isinstance(is_false_positive, bool), "is_false_positive must be a boolean"

    query = text("""
        INSERT INTO fp_labels (id, finding_id, is_false_positive, labeler, reason, created_at)
        VALUES (:id, :finding_id, :is_fp, :labeler, :reason, :created_at)
    """)
    
    try:
        with engine.begin() as conn:
            conn.execute(query, {
                "id": str(uuid.uuid4()),
                "finding_id": finding_id,
                "is_fp": is_false_positive,
                "labeler": "system_user",
                "reason": "Manual Triage",
                "created_at": datetime.now().astimezone()
            })
        logger.info(f"Successfully classified finding {finding_id} as FP={is_false_positive}")
        return True
    except SQLAlchemyError as e:
        logger.error(f"Failed to submit classification for {finding_id}: {e}")
        return False

def get_completion_metrics(engine: Engine) -> int:
    """Retrieves the total number of processed findings."""
    query = text("SELECT COUNT(*) FROM fp_labels;")
    try:
        with engine.connect() as conn:
            result = conn.execute(query).scalar()
            return int(result) if result else 0
    except SQLAlchemyError as e:
        logger.error(f"Failed to fetch metrics: {e}")
        return 0

def main() -> None:
    """Main Streamlit application loop."""
    st.set_page_config(page_title="AppSec Triage", layout="centered")
    
    # Header
    st.title("Vulnerability Triage Interface")
    st.markdown("Classify findings to generate training data for the FP Reduction Pipeline.")

    # DB Init
    engine = initialize_database()
    if not engine:
        st.error("System Error: Unable to connect to the database. Check system logs.")
        sys.exit(1)

    # Fetch Data
    finding_df = fetch_unprocessed_finding(engine)

    if finding_df.empty:
        st.success("Queue empty. All current findings have been classified.")
    else:
        row = finding_df.iloc[0]
        
        # UI Structure
        st.markdown("### Asset Information")
        st.code(f"Package:   {row['package_name']} (v{row['package_version']})\nEcosystem: {row['ecosystem']}")
        
        st.markdown("### Vulnerability Details")
        st.code(f"CVE ID:    {row['cve_id']}\nCVSS Base: {row['cvss_score']}")
        st.info(row['description'])
        
        st.markdown("---")
        
        # Action Inputs
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Mark as False Positive", use_container_width=True):
                if submit_classification(engine, str(row['finding_id']), True):
                    st.rerun()
                else:
                    st.error("Database transaction failed.")
                
        with col2:
            if st.button("Mark as True Positive", use_container_width=True):
                if submit_classification(engine, str(row['finding_id']), False):
                    st.rerun()
                else:
                    st.error("Database transaction failed.")
                
        # Metrics
        processed_count = get_completion_metrics(engine)
        st.caption(f"System metrics: {processed_count} records classified.")

if __name__ == "__main__":
    main()
#FastAPI for building the backend...

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Literal
import os
from google import genai
from dotenv import load_dotenv 
from parser import parse_and_detect 
from fastapi.middleware.cors import CORSMiddleware
import base64
import io
import docx
from pypdf import PdfReader

# Load environment variables from the .env file
load_dotenv()

app = FastAPI(title="AI Secure Data Intelligence Platform")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Request Models ---
class AnalyzeOptions(BaseModel):
    mask: bool = False
    block_high_risk: bool = False
    log_analysis: bool = False

class AnalyzeRequest(BaseModel):
    #input types include text, file, sql, chat, log
    input_type: Literal["text", "file", "sql", "chat", "log","pdf","docx"]
    content: str
    options: AnalyzeOptions

# --- Response Models ---
class Finding(BaseModel):
    type: str
    risk: Literal["low", "medium", "high", "critical"]
    line: Optional[int] = None
    value: Optional[str] = None 

class AnalyzeResponse(BaseModel):
    summary: str
    content_type: str
    findings: List[Finding]
    risk_score: int
    risk_level: Literal["low", "medium", "high", "critical"]
    action: str
    insights: List[str]


#this function generates AI based insights...Used Gemini API for this task..
def generate_ai_insights(findings: list, content: str):
    """
    Passes the parsed findings and log content to an LLM to generate 
    meaningful insights and a summary.
    """
    if not findings:
        return "Log analysis complete. No sensitive data or anomalies detected.", ["No risks identified."]

    #Defining the prompt...
    prompt = f"""
    You are an AI Security Log Analyzer. Review the following security findings extracted from a system log:
    {findings}
    
    Provide your response in exactly two parts separated by a pipeline '|':
    1. A concise, 1-sentence summary of the risks found.
    2. A comma-separated list of 2-3 specific, actionable insights or warnings based on these findings. Do not use generic phrases.
    """

    #LLM Call
    try:
        client = genai.Client() 
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        raw_text = response.text
    except Exception as e:
        print(f"AI API Error: {e}")
        raw_text = "Log analysis revealed potential security risks | Please review logs manually due to AI service disruption"

    # Parse the LLM response
    try:
        parts = raw_text.split('|')
        summary = parts[0].strip()
        insights_raw = parts[1].split(',')
        insights = [insight.strip() for insight in insights_raw if insight.strip()]
        return summary, insights
    except Exception:
        return "Log analysis revealed potential security risks.", ["Review logs for exposed secrets and stack traces."]


#function to calculate risk score and level based on findings..
def calculate_risk(findings: list):
    """
    Calculates the total risk score and determines the overall risk level
    based on the findings from the parser.
    """
    if not findings:
        return 0, "low"

    # Assigned random risk scores for each category based on the example given in the document..
    weights = {
        "low": 1,
        "medium": 3,
        "high": 4,
        "critical": 7
    }

    total_score = 0
    highest_severity_level = 0
    
    # Map levels to numbers to easily find the max severity
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    reverse_severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}

    for finding in findings:
        risk = finding.get("risk", "low")
        total_score += weights.get(risk, 0)
        
        # Track the highest severity found
        current_severity = severity_map.get(risk, 1)
        if current_severity > highest_severity_level:
            highest_severity_level = current_severity

    # Determine overall risk level based on the highest severity found
    overall_level = reverse_severity_map.get(highest_severity_level, "low")

    return total_score, overall_level


#function to extract text from pdfs and doc files..
def extract_text_from_binary(base64_content: str, file_type: str) -> str:
    """Decodes Base64 and extracts text from PDF or DOCX files."""
    # Remove the Data URL prefix the frontend adds (e.g., "data:application/pdf;base64,")
    if "," in base64_content:
        base64_content = base64_content.split(",")[1]
        
    file_bytes = base64.b64decode(base64_content)
    extracted_text = ""
    
    try:
        if file_type == "pdf":
            reader = PdfReader(io.BytesIO(file_bytes))
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    extracted_text += text + "\n"
        elif file_type == "docx":
            doc = docx.Document(io.BytesIO(file_bytes))
            for para in doc.paragraphs:
                extracted_text += para.text + "\n"
    except Exception as e:
        print(f"Extraction Error: {e}")
        return "Error extracting text from file."
        
    return extracted_text

#API Endpoint...
@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_data(request: AnalyzeRequest):
    """
    Main endpoint for data and log analysis.
    """
    # 1. Validation & Routing
    if request.input_type == "log" and not request.options.log_analysis:
        raise HTTPException(status_code=400, detail="log_analysis option must be true for log input")

    # 2. Extraction & Detection (UPDATED FOR PDF/DOCX)
    content_to_parse = request.content
    
    # If it's a binary file, extract the text first!
    if request.input_type in ["pdf", "docx"]:
        content_to_parse = extract_text_from_binary(request.content, request.input_type)
        
    findings = parse_and_detect(content_to_parse)
    
    # 3. AI Insights (Passed content_to_parse here)
    summary, insights = generate_ai_insights(findings, content_to_parse)
    
    # 4. Risk Engine
    risk_score, risk_level = calculate_risk(findings)
    
    # 5. Policy Engine
    action = "blocked" if request.options.block_high_risk and risk_level in ["high", "critical"] else "masked"

    # Construct the final response matching the required format
    return AnalyzeResponse(
        summary=summary,
        content_type=request.input_type,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        action=action,
        insights=insights
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
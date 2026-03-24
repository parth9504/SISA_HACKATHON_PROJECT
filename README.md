
# 🛡️ AI Secure Data Intelligence Platform

An advanced, full-stack security platform designed to act as an AI Gateway, Data Scanner, Log Analyzer, and Risk Engine. This system ingests multi-format data, detects sensitive leaks, calculates risk scores, and leverages Generative AI to provide actionable security insights.

# Key Features
* **Multi-Input Ingestion:** Seamlessly accepts raw text pastes or file uploads, supporting `.log`, `.txt`, `.sql`, `.pdf`, and `.doc` formats.

* **Intelligent Log Analyzer:** A robust, regex-powered backend engine that scans data line-by-line to detect and extract:
  * **Critical Risk:** Plain text passwords.
  * **High Risk:** Exposed API keys and authentication tokens.
  * **Medium Risk:** System error leaks and stack traces.
  * **Low Risk:** Emails and other information.
* **Dynamic Risk Engine:** Automatically aggregates vulnerability weights to assign a total risk score and an overarching severity level to the analyzed data.
* **AI-Powered Insights:** Integrates with Google's Gemini LLM to generate concise summaries of log activity, detect anomalies, and provide specific, actionable remediation steps based on the parsed findings.
* **Interactive Visualization Dashboard:** A responsive, single-page UI featuring drag-and-drop uploads, an AI Insights panel, and a syntax-highlighted log viewer that visually flags vulnerable lines .


# 🛠️ Tech Stack

* **Backend:** Python, FastAPI, Pydantic (Used for Strict Schema Validation)
* **AI Integration:** Google GenAI (`gemini-2.5-flash`)
* **Data Processing:** Python `re` (Regex Engine)
* **Frontend:** HTML5, Vanilla JavaScript, Tailwind CSS (via CDN)

# 📂 Project Structure

    ├──📂 test_files    #Includes test files of various formats which can be used for testing
    ├── main.py          # FastAPI application, routing, Risk Engine, and AI Integration
    ├── parser.py        # Core regex logic for extracting sensitive data line-by-line
    ├── index.html       # Single-page frontend dashboard with Tailwind & JS
    ├── .env             # Environment variables (Create this file and add Gemini API Key)
    ├── requirements.txt  #Includes all the libraries to be installed.
    └── README.md        # Project documentation

# 🚀 How to Run the Project
Follow these steps to run the platform locally on your machine.

* **Prerequisites**

    Ensure you have the following installed:
    * Python 3.8+
    * An active Google Gemini API Key

* **Backend Setup**

    Open your terminal and navigate to the project directory.

    **Install the required dependencies:**

        pip install fastapi uvicorn pydantic google-genai python-dotenv pypdf python-docx


    **Configure the Environment Variables:**

    * Create a file named .env in the root directory and add your Gemini API key:

        `GEMINI_API_KEY="your_actual_api_key_here"`

    **Start the Server:**

    Run the FastAPI application using Uvicorn:

        python main.py

    The backend API will now be running on http://localhost:8000.

* **Frontend Setup**

    * Because the frontend is a lightweight, dependency-free HTML file, no build process is required!

    * Ensure the Python backend is actively running in your terminal.

   * Double-click the index.html file to open it in your preferred web browser (Chrome, Edge, Firefox).
 
     <img width="526" height="389" alt="image" src="https://github.com/user-attachments/assets/fd8e0e18-ecc0-4284-bf3a-bfc357088c90" />


* **Testing the Platform**

    In the browser dashboard, use the Direct Text Input box or the Drag & Drop zone.

* **Outputs**

  <img width="1036" height="804" alt="image" src="https://github.com/user-attachments/assets/b30ba2c2-9c41-4543-b429-a4a12af2fe3b" />


  <img width="1030" height="796" alt="image" src="https://github.com/user-attachments/assets/6f6fdda1-b5fc-45f6-b6dc-99e064950b67" />




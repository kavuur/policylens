# PolicyLensAI — Intelligent Policy Analysis Platform

PolicyLensAI is an AI-enabled web application that helps policy researchers analyze, compare, and improve policy documents. It integrates document processing, evidence retrieval, and large-language-model (LLM) analysis into an interactive research workflow. Built with modern RAG services, the app supports structured policy review, automated excerpt extraction, and live drafting assistance.

---

### 🧭 Core Features

* **Policy Upload & Extraction**
  Upload policy PDFs or Word files. The system automatically extracts text and structures it into analyzable sections.

* **AI-Driven Analysis**
  Uses OpenAI’s GPT-4o model to identify key policy excerpts, align them to codebook frameworks, and generate improvement recommendations.

* **Evidence Integration**
  Automatically derives keywords and queries Google Custom Search to retrieve academic and grey literature supporting or challenging policy content.

* **Framework Comparison**
  Annotates aligned and misaligned policy segments, highlighting excerpts directly in the rendered PDF, with hover-based pop-up explanations.

* **Interactive Research Tools**
  Create and edit projects, codebooks, codes, subcodes, and excerpts. Collaborate with other users, manage media files, and view structured comparisons.

* **Live Writing Assistant**
  A “Live Writing” mode suggests evidence-based sentences and structures in real time while drafting policy briefs, frameworks, or strategic plans.

* **Data Management**
  Includes migration and schema scripts for updating database structures, sample data generation utilities, and dummy excerpt populators.

---

### ⚙️ Tech Stack

* **Backend:** Flask, SQLAlchemy, Flask-Migrate
* **Frontend:** Jinja2, Bootstrap, JavaScript
* **Database:** SQLite — supports PostgreSQL migration
* **AI Services:** OpenAI GPT-4o, Google Custom Search API
* **Embedding/Indexing:** Sentence-Transformers (MiniLM-L6-v2), FAISS
* **Environment:** Python 3.10+ with `.env` for API keys

---

### 🚀 Quick Start

1. **Clone & Setup**

   ```bash
   git clone https://github.com/<your-username>/policylensai.git
   cd policylensai
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure Environment**
   Edit `.env`:

   ```
   OPENAI_API_KEY=<your_openai_key>
   GOOGLE_API_KEY=<your_google_key>
   GOOGLE_CSE_ID=<your_cse_id>
   ```

3. **Initialize Database**

   ```bash
   python init_db.py
   python sample_data.py
   ```

4. **Run the App**

   ```bash
   python run.py
   ```

   Then open [http://localhost:5000](http://localhost:5000)

---

### 🧩 Key Modules

* `app.py` — Main Flask application and route definitions
* `services/analysis.py` — Handles LLM-based policy–framework comparison
* `services/policy_analyzer.py` — Evidence retrieval and improvement generation
* `models/models.py` — ORM schema for users, projects, media, and excerpts
* `forms.py` — Flask-WTF form definitions for uploads, profiles, and projects
* `sample_data.py` — Generates realistic sample content for testing

---

### 🧠 Authors

Developed under the **PolicyLensAI** initiative at the **African Population and Health Research Center (APHRC)**
Lead AI Expert: **Dr. Tatenda Duncan Kavu**, Lead Full Stack Developer: **David Wanambwa**, Policy Expert: **Henry Owoko Odero** 

---

### 📜 License

© 2025 APHRC. All rights reserved.
For research and non-commercial use only.

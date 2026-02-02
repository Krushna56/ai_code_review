// DOM Elements
const uploadArea = document.getElementById("uploadArea");
const fileInput = document.getElementById("fileInput");
const browseBtn = document.getElementById("browseBtn");
const uploadCard = document.getElementById("uploadCard");
const loadingState = document.getElementById("loadingState");
const resultsSection = document.getElementById("resultsSection");
const errorMessage = document.getElementById("errorMessage");
const newDocBtn = document.getElementById("newDocBtn");
const closeErrorBtn = document.getElementById("closeErrorBtn");

// Event Listeners
browseBtn.addEventListener("click", (e) => {
  e.stopPropagation(); // Prevent event from bubbling to uploadArea
  fileInput.click();
});

// Only trigger on uploadArea direct clicks, not on child elements
uploadArea.addEventListener("click", (e) => {
  // Only open file dialog if clicking the uploadArea itself, not its children
  if (e.target === uploadArea || e.target.classList.contains('upload-icon') || 
      e.target.tagName === 'H2' || e.target.tagName === 'P' && e.target.parentElement === uploadArea) {
    fileInput.click();
  }
});

fileInput.addEventListener("change", handleFileSelect);
newDocBtn.addEventListener("click", resetUpload);
closeErrorBtn.addEventListener("click", hideError);

// Drag and Drop
uploadArea.addEventListener("dragover", (e) => {
  e.preventDefault();
  uploadArea.classList.add("drag-over");
});

uploadArea.addEventListener("dragleave", () => {
  uploadArea.classList.remove("drag-over");
});

uploadArea.addEventListener("drop", (e) => {
  e.preventDefault();
  uploadArea.classList.remove("drag-over");

  const files = e.dataTransfer.files;
  if (files.length > 0) {
    fileInput.files = files;
    handleFileSelect({ target: { files: files } });
  }
});

// Handle File Selection
function handleFileSelect(event) {
  const file = event.target.files[0];

  if (!file) return;

  // Validate file type
  const validTypes = [
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
    "text/plain",
  ];
  const validExtensions = [
    ".pdf", ".docx", ".doc", ".txt",
    // Code files
    ".py", ".js", ".java", ".cpp", ".c", ".cs", ".go", ".rb", ".php",
    ".ts", ".jsx", ".tsx", ".swift", ".kt", ".rs", ".scala", ".r",
    ".m", ".h", ".html", ".css", ".sql", ".sh", ".bash"
  ];

  const fileExtension = "." + file.name.split(".").pop().toLowerCase();

  if (
    !validTypes.includes(file.type) &&
    !validExtensions.includes(fileExtension)
  ) {
    showError("Invalid file type. Please upload supported document or code files.");
    return;
  }

  // Validate file size (50MB max)
  const maxSize = 50 * 1024 * 1024;
  if (file.size > maxSize) {
    showError("File size exceeds 50MB limit. Please upload a smaller file.");
    return;
  }

  // Upload file
  uploadFile(file);
}

// Upload File to Server
async function uploadFile(file) {
  // Show loading state
  uploadArea.style.display = "none";
  loadingState.style.display = "block";

  const formData = new FormData();
  formData.append("file", file);
  
  // Add document type
  const documentTypeSelect = document.getElementById("documentTypeSelect");
  if (documentTypeSelect && documentTypeSelect.value) {
    formData.append("document_type", documentTypeSelect.value);
  }
  
  // Add summary type (quick/detailed/auto)
  const summaryTypeSelect = document.getElementById("summaryTypeSelect");
  if (summaryTypeSelect && summaryTypeSelect.value) {
    formData.append("summary_type", summaryTypeSelect.value);
  }

  try {
    const response = await fetch("/upload", {
      method: "POST",
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Failed to process document");
    }

    // Display results
    displayResults(data);
  } catch (error) {
    console.error("Upload error:", error);
    showError(
      error.message || "An error occurred while processing your document"
    );
    resetUpload();
  }
}

// Display Results
function displayResults(data) {
  // Hide upload card
  uploadCard.style.display = "none";

  // Populate basic info
  document.getElementById("docName").textContent = data.filename;
  document.getElementById("pageCount").textContent = data.page_count;

  // Check if it's a code file or document
  if (data.file_type === 'code') {
    // Handle code analysis results
    displayCodeAnalysis(data);
  } else {
    // Handle document analysis results
    displayDocumentAnalysis(data);
  }

  // Show results section with animation
  resultsSection.style.display = "block";

  // Scroll to results
  setTimeout(() => {
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 100);
}

// Display Code Analysis Results
function displayCodeAnalysis(data) {
  // Hide document-specific sections
  document.getElementById("overviewSection").style.display = "none";
  document.getElementById("legalAnalysisSection").style.display = "none";
  document.getElementById("lawReferencesSection").style.display = "none";
  document.getElementById("keyElementsSection").style.display = "none";
  
  // Update info panel for code
  document.getElementById("wordCount").parentElement.querySelector(".info-label").textContent = "Lines:";
  document.getElementById("wordCount").textContent = data.line_count;
  
  // Hide summary section for code files
  document.querySelector(".summary-section").style.display = "none";
  
  // Show code analysis section
  const codeAnalysisSection = document.getElementById("codeAnalysisSection");
  codeAnalysisSection.style.display = "block";
  
  // Display metrics
  if (data.metrics) {
    const metricsGrid = document.getElementById("metricsGrid");
    metricsGrid.innerHTML = "";
    
    const metrics = [
      { label: "Language", value: data.language },
      { label: "Total Lines", value: data.metrics.total_lines },
      { label: "Code Lines", value: data.metrics.code_lines },
      { label: "Functions", value: data.metrics.functions },
      { label: "Classes", value: data.metrics.classes },
      { label: "Comments", value: data.metrics.comment_lines }
    ];
    
    metrics.forEach(metric => {
      const metricDiv = document.createElement("div");
      metricDiv.className = "metric-item";
      metricDiv.innerHTML = `
        <div class="metric-label">${metric.label}</div>
        <div class="metric-value">${metric.value}</div>
      `;
      metricsGrid.appendChild(metricDiv);
    });
  }
  
  // Display logic summary
  if (data.logic_summary) {
    const logicContent = document.getElementById("logicContent");
    logicContent.innerHTML = "";
    
    const logic = data.logic_summary;
    
    // Main purpose
    const purposeDiv = document.createElement("div");
    purposeDiv.className = "logic-item";
    purposeDiv.innerHTML = `<strong>Purpose:</strong> ${logic.main_purpose}`;
    logicContent.appendChild(purposeDiv);
    
    // Logic flow
    if (logic.logic_flow) {
      const flowDiv = document.createElement("div");
      flowDiv.className = "logic-item";
      flowDiv.innerHTML = `<strong>Flow:</strong> ${logic.logic_flow}`;
      logicContent.appendChild(flowDiv);
    }
    
    // Key functionalities
    if (logic.key_functionalities && logic.key_functionalities.length > 0) {
      const functDiv = document.createElement("div");
      functDiv.className = "logic-item";
      functDiv.innerHTML = `<strong>Key Features:</strong><ul>${logic.key_functionalities.map(f => `<li>${f}</li>`).join('')}</ul>`;
      logicContent.appendChild(functDiv);
    }
    
    // Algorithms
    if (logic.algorithms_used && logic.algorithms_used.length > 0) {
      const algoDiv = document.createElement("div");
      algoDiv.className = "logic-item";
      algoDiv.innerHTML = `<strong>Algorithms:</strong> ${logic.algorithms_used.join(', ')}`;
      logicContent.appendChild(algoDiv);
    }
  }
  
  // Display architecture
  if (data.architecture) {
    const archContent = document.getElementById("architectureContent");
    archContent.innerHTML = "";
    
    const arch = data.architecture;
    
    // Structure type
    const typeDiv = document.createElement("div");
    typeDiv.className = "arch-item";
    typeDiv.innerHTML = `<strong>Structure:</strong> ${arch.structure_type}`;
    archContent.appendChild(typeDiv);
    
    // Summary
    if (arch.architecture_summary) {
      const summaryDiv = document.createElement("div");
      summaryDiv.className = "arch-item";
      summaryDiv.innerHTML = `<strong>Overview:</strong> ${arch.architecture_summary}`;
      archContent.appendChild(summaryDiv);
    }
    
    // Components
    if (arch.components && arch.components.length > 0) {
      const compDiv = document.createElement("div");
      compDiv.className = "arch-item";
      compDiv.innerHTML = `<strong>Components:</strong>`;
      const compList = document.createElement("ul");
      arch.components.forEach(comp => {
        const li = document.createElement("li");
        li.innerHTML = `<strong>${comp.name}</strong> (${comp.type}): ${comp.purpose}`;
        compList.appendChild(li);
      });
      compDiv.appendChild(compList);
      archContent.appendChild(compDiv);
    }
    
    // Dependencies
    if (arch.external_dependencies && arch.external_dependencies.length > 0) {
      const depDiv = document.createElement("div");
      depDiv.className = "arch-item";
      depDiv.innerHTML = `<strong>Dependencies:</strong> ${arch.external_dependencies.join(', ')}`;
      archContent.appendChild(depDiv);
    }
    
    // Design patterns
    if (arch.design_patterns && arch.design_patterns.length > 0) {
      const patternDiv = document.createElement("div");
      patternDiv.className = "arch-item";
      patternDiv.innerHTML = `<strong>Design Patterns:</strong> ${arch.design_patterns.join(', ')}`;
      archContent.appendChild(patternDiv);
    }
  }
  
  // Display diagram
  if (data.diagram) {
    const diagramContainer = document.getElementById("diagramContainer");
    diagramContainer.innerHTML = "";
    
    const diagramDiv = document.createElement("div");
    diagramDiv.className = "mermaid";
    diagramDiv.textContent = data.diagram;
    diagramContainer.appendChild(diagramDiv);
    
    // Render mermaid diagram
    if (window.mermaid) {
      setTimeout(() => {
        window.mermaid.run({
          querySelector: '#diagramContainer .mermaid'
        });
      }, 100);
    }
  }
}

// Display Document Analysis Results
function displayDocumentAnalysis(data) {
  // Hide code-specific sections
  document.getElementById("codeAnalysisSection").style.display = "none";
  
  // Show document sections
  document.getElementById("keyElementsSection").style.display = "block";
  document.querySelector(".summary-section").style.display = "block";
  
  // Update word count
  document.getElementById("wordCount").parentElement.querySelector(".info-label").textContent = "Words:";
  document.getElementById("wordCount").textContent = data.word_count.toLocaleString();

  // Display summary
  const summaryContent = document.getElementById("summaryContent");
  summaryContent.textContent = data.summary;

  // Display detailed overview if available
  const overviewSection = document.getElementById("overviewSection");
  const overviewContent = document.getElementById("overviewContent");
  if (data.detailed_overview) {
    overviewContent.textContent = data.detailed_overview;
    overviewSection.style.display = "block";
  } else {
    overviewSection.style.display = "none";
  }

  // Display legal analysis if available (legal documents only)
  const legalAnalysisSection = document.getElementById("legalAnalysisSection");
  const lawReferencesSection = document.getElementById("lawReferencesSection");
  
  if (data.legal_analysis) {
    const conflictsContainer = document.getElementById("legalConflictsContainer");
    const loopholesContainer = document.getElementById("legalLoopholesContainer");
    
    // Clear previous content
    conflictsContainer.innerHTML = "";
    loopholesContainer.innerHTML = "";
    
    // Display conflicts
    if (data.legal_analysis.conflicts && data.legal_analysis.conflicts.length > 0) {
      data.legal_analysis.conflicts.forEach(conflict => {
        const conflictDiv = document.createElement("div");
        conflictDiv.className = "conflict-item";
        conflictDiv.innerHTML = `
          <h4>⚔️ ${conflict.issue}</h4>
          <p class="conflict-detail"><strong>Clause A:</strong> ${conflict.clause_a}</p>
          <p class="conflict-detail"><strong>Clause B:</strong> ${conflict.clause_b}</p>
          <p class="conflict-detail"><strong>Impact:</strong> ${conflict.explanation}</p>
        `;
        conflictsContainer.appendChild(conflictDiv);
      });
    }
    
    // Display loopholes
    if (data.legal_analysis.loopholes && data.legal_analysis.loopholes.length > 0) {
      data.legal_analysis.loopholes.forEach(loophole => {
        const loopholeDiv = document.createElement("div");
        loopholeDiv.className = "loophole-item";
        loopholeDiv.innerHTML = `
          <h4>🔓 ${loophole.issue}</h4>
          <p class="loophole-detail"><strong>Location:</strong> ${loophole.location}</p>
          <p class="loophole-detail"><strong>Risk:</strong> ${loophole.risk}</p>
        `;
        loopholesContainer.appendChild(loopholeDiv);
      });
    }
    
    legalAnalysisSection.style.display = "block";
  } else {
    legalAnalysisSection.style.display = "none";
  }
  
  // Display law references if available
  if (data.law_references && data.law_references.length > 0) {
    const lawRefsContainer = document.getElementById("lawReferencesContainer");
    lawRefsContainer.innerHTML = "";
    
    data.law_references.forEach(lawRef => {
      const lawDiv = document.createElement("div");
      lawDiv.className = "law-reference-item";
      lawDiv.innerHTML = `
        <div class="law-name">📜 ${lawRef.reference}</div>
        <div class="law-explanation">${lawRef.explanation}</div>
      `;
      lawRefsContainer.appendChild(lawDiv);
    });
    
    lawReferencesSection.style.display = "block";
  } else {
    lawReferencesSection.style.display = "none";
  }

  // Display key elements
  const keyElementsGrid = document.getElementById("keyElementsGrid");
  keyElementsGrid.innerHTML = "";

  if (data.key_elements && data.key_elements.length > 0) {
    data.key_elements.forEach((element, index) => {
      const elementDiv = document.createElement("div");
      elementDiv.className = "key-element";
      elementDiv.textContent = element;
      elementDiv.style.animationDelay = `${index * 0.1}s`;
      keyElementsGrid.appendChild(elementDiv);
    });
  }
}

// Reset Upload
function resetUpload() {
  // Clear file input
  fileInput.value = "";
  
  // Reset document type to general
  const documentTypeSelect = document.getElementById("documentTypeSelect");
  if (documentTypeSelect) {
    documentTypeSelect.value = "general";
  }
  
  // Reset summary type to auto
  const summaryTypeSelect = document.getElementById("summaryTypeSelect");
  if (summaryTypeSelect) {
    summaryTypeSelect.value = "auto";
  }

  // Reset UI
  uploadCard.style.display = "block";
  uploadArea.style.display = "block";
  loadingState.style.display = "none";
  resultsSection.style.display = "none";

  // Scroll to top
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// Show Error Message
function showError(message) {
  const errorText = document.getElementById("errorText");
  errorText.textContent = message;
  errorMessage.style.display = "block";

  // Auto-hide after 5 seconds
  setTimeout(hideError, 5000);
}

// Hide Error Message
function hideError() {
  errorMessage.style.display = "none";
}

// Prevent default drag behavior on document
document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => e.preventDefault());

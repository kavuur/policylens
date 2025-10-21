let quill;
let debounceTimer;
let currentEvidence = [];
let selectedProduct = '';
let savedCursorPos = 0;  // Track cursor for insertion

// Initialize Quill Editor
$(document).ready(function() {
    const toolbarOptions = [
        ['bold', 'italic', 'underline'], ['link'], ['blockquote'], [{ 'list': 'ordered'}, { 'list': 'bullet' }]
    ];
    quill = new Quill('#editor', {
        theme: 'snow',
        modules: { toolbar: toolbarOptions },
        placeholder: 'Select a policy product to generate a structure, then start drafting...'
    });

    // Product selection handler (unchanged)
    $('#productSelect').on('change', function() {
        const productType = $(this).val();
        if (!productType) return;

        selectedProduct = productType;
        console.log('Selected product:', productType);

        quill.setText('Generating structure...');

        $.ajax({
            url: '/get_structure',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ product_type: productType }),
            success: function(response) {
                if (response.success) {
                    populateEditor(response.outline);
                    displayEvidence(response.evidence);
                    currentEvidence = response.evidence;
                    console.log('Structure loaded:', response.outline);
                } else {
                    quill.setText('Error loading structure: ' + (response.error || 'Unknown'));
                }
            },
            error: function(xhr) {
                quill.setText('Failed to load structure: ' + (xhr.responseJSON?.error || 'AJAX error'));
                console.error('Structure AJAX error:', xhr);
            }
        });
    });

    // Updated: Typing listener - save cursor
    quill.on('text-change', function(delta, oldDelta, source) {
        if (source === 'user') {
            savedCursorPos = quill.getSelection(true)?.index || quill.getLength();  // Save pos
            console.log('Cursor saved on text-change:', savedCursorPos);  // Debug
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(getSuggestions, 3000);  // Increased to 3s for rate limit
        }
    });

    quill.on('selection-change', function(range) {
        if (range && range.length === 0) {
            savedCursorPos = range.index;
            console.log('Cursor saved on selection-change:', savedCursorPos);  // Debug
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(getSuggestions, 3000);
        }
    });
});

// Updated: Get section-specific context (unchanged)
function getSuggestions() {
    const fullText = quill.getText().trim();
    const wordCount = fullText.split(/\s+/).length;
    if (wordCount < 10) {
        console.log(`Full text too short (${wordCount} words < 10), skipping`);
        return;
    }

    const range = quill.getSelection(true);  // Force get current position
    if (!range || range.index < 0) {
        console.log('No valid selection, skipping');
        return;
    }

    // Get current line (paragraph/section)
    const [line, offset] = quill.getLine(range.index);
    const lineText = line.domNode.textContent.trim();
    const lineStart = quill.getIndex(line);

    // Get prior context (previous line + current for flow)
    const priorStart = Math.max(0, lineStart - 300);  // ~300 chars before line
    const priorText = quill.getText(priorStart, lineStart - priorStart + lineText.length);
    const sectionContext = priorText.trim();

    console.log('Section context (words:', sectionContext.split(/\s+/).length, '):', sectionContext);

    $('#suggestionsPanel').html('<p class="text-muted"><span class="spinner-border spinner-border-sm me-1"></span>Generating section-specific suggestions...</p>');

    $.ajax({
        url: '/live_suggest',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            context: sectionContext,  // Now section-focused
            product_type: selectedProduct
        }),
        success: function(response) {
            console.log('AJAX success:', response);
            if (response.success) {
                displaySuggestions(response.suggestions);
                displayEvidence(response.evidence);
                currentEvidence = response.evidence;
            } else {
                console.error('Suggestion error:', response.error);
                $('#suggestionsPanel').html('<p class="text-danger">Error: ' + (response.error || 'Unknown') + '</p>');
            }
        },
        error: function(xhr, status, error) {
            console.error('AJAX error:', { status, error, response: xhr.responseJSON });
            $('#suggestionsPanel').html('<p class="text-danger">AJAX failed: ' + (xhr.responseJSON?.error || error) + '</p>');
        }
    });
}

// Existing functions (unchanged except insertSuggestion fix)
function populateEditor(outline) {
    let formattedText = outline
        .replace(/# (.*)/g, '# $1\n')
        .replace(/## (.*)/g, '## $1\n')
        .replace(/### (.*)/g, '### $1\n')
        .replace(/\*\*(.*)\*\*/g, '**$1**')
        .replace(/\*(.*)\*/g, '*$1*');

    quill.setText(formattedText);
    quill.setSelection(quill.getLength());
}

function displaySuggestions(suggestions) {
    if (!suggestions || suggestions.length === 0) {
        $('#suggestionsPanel').html('<p class="text-muted">No suggestions available.</p>');
        return;
    }
    let html = '<ul class="list-unstyled">';
    suggestions.forEach((sug, i) => {
        html += `<li class="mb-2 p-2 bg-white rounded shadow-sm border cursor-pointer" onclick="insertSuggestion('${i}')">${sug}</li>`;
    });
    html += '</ul>';
    $('#suggestionsPanel').html(html);
    console.log('Suggestions displayed:', suggestions);
}

function insertSuggestion(index) {
    const suggestion = $('#suggestionsPanel li').eq(parseInt(index)).text().trim();
    const range = { index: savedCursorPos || quill.getLength() };  // Use saved pos
    quill.setSelection(range.index);  // Restore cursor first
    quill.insertText(range.index, suggestion + ' ');
    quill.setSelection(range.index + suggestion.length + 1);  // Move cursor after insert
    savedCursorPos = range.index + suggestion.length + 1;  // Update saved
    console.log('Inserted at saved pos', range.index, ':', suggestion);
}

function displayEvidence(evidence) {
    if (!evidence || evidence.length === 0) {
        $('#evidencePanel').html('<p class="text-muted small">No evidence yet.</p>');
        return;
    }
    let html = '<div class="list-group list-group-flush">';
    evidence.forEach(item => {
        const isAcademic = item.source.includes('nih.gov') || item.source.includes('who.int') || item.source.includes('jstor.org') || item.source.includes('sciencedirect.com') || item.source.includes('pubmed.ncbi.nlm.nih.gov');
        const badge = isAcademic ? '<span class="badge bg-primary ms-1">Academic</span>' : '';
        html += `
            <div class="list-group-item d-flex justify-content-between align-items-start">
                <div>
                    <strong>${item.title}</strong><br>
                    <small class="text-muted">${item.snippet}</small>
                </div>
                <a href="${item.url}" target="_blank" class="btn btn-sm btn-outline-secondary">${badge}View</a>
            </div>
        `;
    });
    html += '</div>';
    $('#evidencePanel').html(html);
    console.log('Evidence displayed:', evidence.length, 'items');
}

function clearEditor() {
    quill.setText('');
    selectedProduct = '';
    $('#productSelect').val('');
    savedCursorPos = 0;  // Reset cursor
    console.log('Editor cleared');
}
function exportDoc() {
    const text = quill.getText();
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `policy_draft_${selectedProduct.replace(/\s+/g, '_').toLowerCase()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    console.log('Exported document');
}
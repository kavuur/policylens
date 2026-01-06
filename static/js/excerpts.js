// Handle Add Excerpt button click
document.addEventListener('DOMContentLoaded', function() {
    const addExcerptBtn = document.getElementById('addExcerptBtn');
    const addFirstExcerptBtn = document.getElementById('addFirstExcerptBtn');
    const excerptModal = new bootstrap.Modal(document.getElementById('excerptModal'));
    const excerptForm = document.getElementById('excerptForm');
    const saveExcerptBtn = document.getElementById('saveExcerptBtn');
    const excerptModalLabel = document.getElementById('excerptModalLabel');
    
    // Show modal for adding a new excerpt
    function showAddExcerptModal() {
        excerptForm.reset();
        excerptForm.dataset.mode = 'add';
        excerptModalLabel.textContent = 'Add New Excerpt';
        excerptModal.show();
    }
    
    // Handle Add Excerpt button click
    if (addExcerptBtn) {
        addExcerptBtn.addEventListener('click', showAddExcerptModal);
    }
    
    // Handle Add First Excerpt button click
    if (addFirstExcerptBtn) {
        addFirstExcerptBtn.addEventListener('click', showAddExcerptModal);
    }
    
    // Handle form submission
    if (excerptForm) {
        excerptForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saving...';
            
            // Get form data
            const formData = new FormData(this);
            
            // Send AJAX request
            fetch('/save_excerpt', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Show success message and reload the page
                    showAlert('Excerpt saved successfully!', 'success');
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                } else {
                    showAlert(data.message || 'Failed to save excerpt', 'danger');
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalBtnText;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('An error occurred while saving the excerpt', 'danger');
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalBtnText;
            });
        });
    }
    
    // Handle view excerpt
    document.addEventListener('click', function(e) {
        if (e.target.closest('.view-excerpt') || e.target.classList.contains('excerpt-row')) {
            e.preventDefault();
            const excerptId = e.target.closest('[data-id]')?.dataset.id || 
                             e.target.closest('.excerpt-row')?.querySelector('.view-excerpt')?.dataset.id;
            
            if (excerptId) {
                // Show loading state
                const viewModal = new bootstrap.Modal(document.getElementById('viewExcerptModal'));
                const modalBody = document.querySelector('#viewExcerptModal .modal-body');
                modalBody.innerHTML = `
                    <div class="text-center my-4">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <p class="mt-2">Loading excerpt details...</p>
                    </div>`;
                
                viewModal.show();
                
                // Fetch excerpt details
                fetch(`/api/excerpts/${excerptId}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            const excerpt = data.excerpt;
                            document.getElementById('viewExcerptMedia').textContent = excerpt.media_name || 'No media';
                            document.getElementById('viewExcerptCode').textContent = excerpt.code || '—';
                            document.getElementById('viewExcerptSubcode').textContent = excerpt.subcode || '—';
                            document.getElementById('viewExcerptText').textContent = excerpt.excerpt || '—';
                            document.getElementById('viewExcerptExplanation').textContent = excerpt.explanation || 'No explanation provided';
                            document.getElementById('viewExcerptUser').textContent = excerpt.user_name || 'Unknown';
                            document.getElementById('viewExcerptDate').textContent = new Date(excerpt.created_at).toLocaleString();
                            
                            // Set up edit button
                            const editBtn = document.getElementById('editExcerptFromView');
                            if (editBtn) {
                                editBtn.onclick = function() {
                                    viewModal.hide();
                                    // Trigger edit functionality
                                    excerptForm.dataset.mode = 'edit';
                                    excerptForm.dataset.excerptId = excerptId;
                                    excerptModalLabel.textContent = 'Edit Excerpt';
                                    
                                    // Populate form
                                    if (excerpt.media_id) {
                                        document.getElementById('media_id').value = excerpt.media_id;
                                    }
                                    if (excerpt.code) {
                                        document.getElementById('code').value = excerpt.code;
                                    }
                                    if (excerpt.subcode) {
                                        document.getElementById('subcode').value = excerpt.subcode;
                                    }
                                    if (excerpt.excerpt) {
                                        document.getElementById('excerpt').value = excerpt.excerpt;
                                    }
                                    if (excerpt.explanation) {
                                        document.getElementById('explanation').value = excerpt.explanation;
                                    }
                                    
                                    excerptModal.show();
                                };
                            }
                        } else {
                            showAlert(data.message || 'Failed to load excerpt details', 'danger');
                            viewModal.hide();
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        showAlert('An error occurred while loading the excerpt', 'danger');
                        viewModal.hide();
                    });
            }
        }
        
        // Handle edit excerpt
        if (e.target.closest('.edit-excerpt')) {
            const excerptId = e.target.closest('.edit-excerpt').dataset.id;
            
            // In a real implementation, you would fetch the excerpt details
            // and populate the form
            console.log('Editing excerpt:', excerptId);
            
            // For now, just show the modal with the excerpt ID
            excerptForm.dataset.mode = 'edit';
            excerptForm.dataset.excerptId = excerptId;
            excerptModalLabel.textContent = 'Edit Excerpt';
            excerptModal.show();
        }
    });
    
    // Reset form when modal is hidden
    document.getElementById('excerptModal').addEventListener('hidden.bs.modal', function () {
        excerptForm.reset();
        delete excerptForm.dataset.mode;
        delete excerptForm.dataset.excerptId;
        
        // Reset any validation messages
        const invalidFields = excerptForm.querySelectorAll('.is-invalid');
        invalidFields.forEach(field => field.classList.remove('is-invalid'));
    });
});

// Helper function to show alerts
function showAlert(message, type = 'success') {
    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    
    // Add alert to the top of the content
    const content = document.querySelector('.tab-content');
    if (content) {
        content.insertAdjacentHTML('afterbegin', alertHtml);
    } else {
        document.body.insertAdjacentHTML('afterbegin', alertHtml);
    }
    
    // Auto-remove alert after 5 seconds
    setTimeout(() => {
        const alert = document.querySelector('.alert');
        if (alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }
    }, 5000);
}

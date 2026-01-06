from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, TextAreaField, SelectField, SubmitField, RadioField, IntegerField, HiddenField, FieldList, FormField, Form, BooleanField
from wtforms.validators import DataRequired, Optional, Length, NumberRange
from flask_login import current_user
from models.models import Project, Media

class MediaUploadForm(FlaskForm):
    # Restrict file types to PDF and Word documents
    file = FileField('File', validators=[
        FileRequired(),
        FileAllowed(['pdf', 'doc', 'docx'], 'Only PDF and Word documents are allowed')
    ])
    description = TextAreaField('Description', validators=[Optional()])
    
    # Category field with the specified options
    category = SelectField('Category', choices=[
        ('', 'Select a category'),
        ('education', 'Education'),
        ('health', 'Health'),
        ('ict', 'ICT'),
        ('government', 'Government'),
        ('security', 'Security'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    
    # Type field
    type = SelectField('Type', choices=[
        ('brief', 'Brief'),
        ('publication', 'Publication'),
        ('law', 'Law'),
        ('policy', 'Policy'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    
    # Visibility field
    visibility = RadioField('Visibility', 
        choices=[
            ('private', 'Private (only you can see)'),
            ('public', 'Public (visible to all users)')
        ],
        default='private',
        validators=[DataRequired()]
    )
    
    project_id = SelectField('Project', coerce=int, validators=[Optional()])
    
    def __init__(self, *args, **kwargs):
        super(MediaUploadForm, self).__init__(*args, **kwargs)
        # This will be populated in the route
        self.project_id.choices = []

class ProfileUpdateForm(FlaskForm):
    """Form for updating user profile information."""
    name = StringField('Full Name', validators=[
        DataRequired('Name is required'),
        Length(max=100, message='Name cannot exceed 100 characters')
    ])
    email = StringField('Email', render_kw={'readonly': True})
    age_group = SelectField('Age Group', choices=[
        ('', 'Select age group'),
        ('18-24', '18-24 years'),
        ('25-34', '25-34 years'),
        ('35-44', '35-44 years'),
        ('45-54', '45-54 years'),
        ('55-64', '55-64 years'),
        ('65+', '65+ years'),
        ('prefer_not_to_say', 'Prefer not to say')
    ], validators=[Optional()])
    sex = SelectField('Gender', choices=[
        ('', 'Select gender'),
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
        ('prefer_not_to_say', 'Prefer not to say')
    ], validators=[Optional()])
    industry = SelectField('Industry', choices=[
        ('', 'Select industry'),
        ('education', 'Education'),
        ('healthcare', 'Healthcare'),
        ('technology', 'Technology'),
        ('government', 'Government'),
        ('finance', 'Finance'),
        ('nonprofit', 'Nonprofit'),
        ('other', 'Other')
    ], validators=[Optional()])
    organization = StringField('Organization', validators=[
        Optional(),
        Length(max=200, message='Organization name cannot exceed 200 characters')
    ])

class PasswordUpdateForm(FlaskForm):
    """Form for updating user password."""
    current_password = StringField('Current Password', validators=[
        DataRequired('Current password is required'),
        Length(min=8, message='Password must be at least 8 characters long')
    ], render_kw={"type": "password"})
    new_password = StringField('New Password', validators=[
        DataRequired('New password is required'),
        Length(min=8, message='Password must be at least 8 characters long')
    ], render_kw={"type": "password"})
    confirm_password = StringField('Confirm New Password', validators=[
        DataRequired('Please confirm your new password')
    ], render_kw={"type": "password"})

    def validate_confirm_password(self, field):
        if self.new_password.data != field.data:
            raise ValidationError('Passwords must match')

class CodebookForm(FlaskForm):
    """Form for creating and editing codebooks."""
    name = StringField('Codebook Name', validators=[
        DataRequired('Codebook name is required'),
        Length(min=3, max=200, message='Codebook name must be between 3 and 200 characters')
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=1000, message='Description cannot exceed 1000 characters')
    ])
    project_id = SelectField('Project (Optional)', coerce=str, validators=[Optional()])
    
    def __init__(self, *args, **kwargs):
        super(CodebookForm, self).__init__(*args, **kwargs)
        # Initialize with empty choices, will be populated in the route
        self.project_id.choices = [('', 'Select a project (optional)')]

class SubSubCodeForm(FlaskForm):
    """Form for sub-subcode items."""
    class Meta:
        csrf = False  # CSRF is handled by the parent form
        
    id = HiddenField('ID')
    subsubcode = StringField('Sub-Subcode', validators=[
        DataRequired('Sub-subcode is required'),
        Length(max=100, message='Sub-subcode cannot exceed 100 characters')
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=1000, message='Description cannot exceed 1000 characters')
    ])
    delete = BooleanField('Delete', default=False)

class SubCodeForm(FlaskForm):
    """Form for subcode items with nested sub-subcodes."""
    class Meta:
        csrf = False  # CSRF is handled by the parent form
        
    id = HiddenField('ID')
    subcode = StringField('Subcode', validators=[
        DataRequired('Subcode is required'),
        Length(max=100, message='Subcode cannot exceed 100 characters')
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=1000, message='Description cannot exceed 1000 characters')
    ])
    delete = BooleanField('Delete', default=False)
    subsubcodes = FieldList(FormField(SubSubCodeForm), min_entries=0)

class CodeForm(FlaskForm):
    """Form for code items with nested subcodes."""
    class Meta:
        csrf = False  # CSRF is handled by the parent form
        
    id = HiddenField('ID')
    code = StringField('Code', validators=[
        DataRequired('Code is required'),
        Length(max=100, message='Code cannot exceed 100 characters')
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=1000, message='Description cannot exceed 1000 characters')
    ])
    delete = BooleanField('Delete', default=False)
    subcodes = FieldList(FormField(SubCodeForm), min_entries=0)

class CodebookEditForm(FlaskForm):
    """Form for editing codebook with nested codes."""
    class Meta:
        csrf = True  # Only the parent form handles CSRF
        
    codes = FieldList(FormField(CodeForm), min_entries=0)
    new_code = StringField('New Code', validators=[
        Optional(),
        Length(max=100, message='Code cannot exceed 100 characters')
    ])
    new_code_description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=1000, message='Description cannot exceed 1000 characters')
    ])
    submit = SubmitField('Save Changes')
    
    def __init__(self, *args, **kwargs):
        super(CodebookEditForm, self).__init__(*args, **kwargs)
        # Ensure CSRF token is available
        if not hasattr(self, 'csrf_token'):
            self.csrf_token = self.meta.csrf_secret if hasattr(self.meta, 'csrf_secret') else ''

class ProjectForm(FlaskForm):
    """Form for creating and editing projects."""
    name = StringField('Project Name', validators=[
        DataRequired('Project name is required'),
        Length(min=3, max=100, message='Project name must be between 3 and 100 characters')
    ])
    description = TextAreaField('Description', validators=[
        Optional(),
        Length(max=500, message='Description cannot exceed 500 characters')
    ])
    def __init__(self, *args, **kwargs):
        super(ProjectForm, self).__init__(*args, **kwargs)
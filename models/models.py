from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer
from flask import current_app

db = SQLAlchemy()

# Association table for project collaborators
project_collaborators = db.Table('project_collaborators',
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('created_at', db.DateTime, server_default=db.func.now())
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(200), nullable=True)  # Will store hashed passwords
    is_active = db.Column(db.Boolean(), default=True)
    is_admin = db.Column(db.Boolean(), default=False)
    is_view_only_admin = db.Column(db.Boolean(), default=False)
    age_group = db.Column(db.String(20), nullable=True)
    sex = db.Column(db.String(20), nullable=True)
    industry = db.Column(db.String(100), nullable=True)
    organization = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    
    # Relationships
    codebooks = db.relationship('Codebook', back_populates='user', cascade='all, delete-orphan')
    policies = db.relationship('PolicyDocument', back_populates='user', cascade='all, delete-orphan')
    research_notes = db.relationship('ResearchNote', back_populates='user', cascade='all, delete-orphan')
    media_items = db.relationship('Media', back_populates='user', cascade='all, delete-orphan')
    excerpts = db.relationship('Excerpt', back_populates='user', cascade='all, delete-orphan')
    # owned_projects is defined via backref in Project.owner
    # collaborative_projects is defined via backref in Project.collaborators
    
    def set_password(self, password):
        """Create hashed password."""
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Check hashed password."""
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password) if self.password_hash else False

    def get_reset_token(self):
        """Generate a password reset token."""
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return serializer.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, max_age=None):
        """Verify password reset token and return user."""
        if max_age is None:
            max_age = current_app.config.get('PASSWORD_RESET_TOKEN_EXPIRY', 86400)
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            data = serializer.loads(token, max_age=max_age)
            return User.query.get(data['user_id'])
        except Exception:
            return None

class PolicyDocument(db.Model):
    __tablename__ = 'policy_document'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    # Relationships
    user = db.relationship('User', back_populates='policies')

class Codebook(db.Model):
    __tablename__ = 'codebook'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', ondelete='CASCADE'), nullable=True, index=True)
    
    # Relationships
    user = db.relationship('User', back_populates='codebooks')
    project = db.relationship('Project', back_populates='codebooks')
    codes = db.relationship('Code', back_populates='codebook', cascade='all, delete-orphan')
    excerpts = db.relationship('Excerpt', back_populates='codebook', cascade='all, delete-orphan')

class Code(db.Model):
    __tablename__ = 'code'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    codebook_id = db.Column(db.Integer, db.ForeignKey('codebook.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Relationships
    codebook = db.relationship('Codebook', back_populates='codes')
    subcodes = db.relationship('SubCode', back_populates='code', cascade='all, delete-orphan')

class SubCode(db.Model):
    __tablename__ = 'subcode'
    id = db.Column(db.Integer, primary_key=True)
    subcode = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    code_id = db.Column(db.Integer, db.ForeignKey('code.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Relationships
    code = db.relationship('Code', back_populates='subcodes')
    subsubcodes = db.relationship('SubSubCode', back_populates='subcode', cascade='all, delete-orphan')

class SubSubCode(db.Model):
    __tablename__ = 'subsubcode'
    id = db.Column(db.Integer, primary_key=True)
    subsubcode = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    subcode_id = db.Column(db.Integer, db.ForeignKey('subcode.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Relationships
    subcode = db.relationship('SubCode', back_populates='subsubcodes')

class ResearchNote(db.Model):
    __tablename__ = 'research_note'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    # Relationships
    user = db.relationship('User', back_populates='research_notes')



class Project(db.Model):
    __tablename__ = 'project'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    excerpts_count = db.Column(db.Integer, default=0)
    media_count = db.Column(db.Integer, default=0)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    owner = db.relationship('User', foreign_keys=[owner_id], backref=db.backref('owned_projects', lazy='dynamic'))
    codebooks = db.relationship('Codebook', back_populates='project', cascade='all, delete-orphan')
    media_items = db.relationship('Media', back_populates='project', cascade='all, delete-orphan')
    excerpts = db.relationship('Excerpt', back_populates='project', cascade='all, delete-orphan')
    collaborators = db.relationship(
        'User',
        secondary=project_collaborators,
        primaryjoin='Project.id == project_collaborators.c.project_id',
        secondaryjoin='User.id == project_collaborators.c.user_id',
        backref=db.backref('collaborative_projects', lazy='dynamic'),
        lazy='select',  # Changed from 'dynamic' to 'select' to support eager loading
        viewonly=False
    )
    
    def __repr__(self):
        return f'<Project {self.name}>'

# This will be moved to the end of the file

class Media(db.Model):
    # Categories
    CATEGORIES = [
        ('education', 'Education'),
        ('health', 'Health'),
        ('ict', 'ICT'),
        ('government', 'Government'),
        ('security', 'Security'),
        ('other', 'Other')
    ]
    
    # Types
    TYPES = [
        ('brief', 'Brief'),
        ('publication', 'Publication'),
        ('law', 'Law'),
        ('policy', 'Policy'),
        ('other', 'Other')
    ]
    
    # Visibility options
    VISIBILITY = [
        ('private', 'Private'),
        ('public', 'Public')
    ]
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    type = db.Column(db.String(50), nullable=False, default='other')
    visibility = db.Column(db.String(20), nullable=False, default='private')
    file_type = db.Column(db.String(100))  # e.g., 'image', 'document', 'video'
    file_size = db.Column(db.BigInteger)  # Store file size in bytes
    uploaded_at = db.Column(db.DateTime, server_default=db.func.now())
    
    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    user = db.relationship('User', back_populates='media_items')
    
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', ondelete='CASCADE'), nullable=True, index=True)
    project = db.relationship('Project', back_populates='media_items')
    
    # One-to-many relationship with descriptors
    descriptors = db.relationship('Descriptor', back_populates='media', cascade='all, delete-orphan')
    
    # One-to-many relationship with excerpts
    excerpts = db.relationship('Excerpt', back_populates='media', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Media {self.filename}>'


class Excerpt(db.Model):
    __tablename__ = 'excerpts'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', ondelete='CASCADE'), nullable=False, index=True)
    media_id = db.Column(db.Integer, db.ForeignKey('media.id', ondelete='CASCADE'), nullable=False, index=True)
    codebook_id = db.Column(db.Integer, db.ForeignKey('codebook.id', ondelete='CASCADE'), nullable=True, index=True)
    code = db.Column(db.String(500), nullable=True)
    subcode = db.Column(db.String(500), nullable=True)
    excerpt = db.Column(db.Text, nullable=False)
    explanation = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    # Relationships
    project = db.relationship('Project', back_populates='excerpts')
    media = db.relationship('Media', back_populates='excerpts')
    codebook = db.relationship('Codebook', back_populates='excerpts')
    user = db.relationship('User', back_populates='excerpts')
    
    def __repr__(self):
        return f'<Excerpt {self.id} - {self.excerpt[:50]}...>'

class Descriptor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), nullable=False)  # e.g., 'year', 'author', 'location'
    value = db.Column(db.Text, nullable=False)       # e.g., '2020', 'John Doe', 'New York'
    
    # Foreign key to Media
    media_id = db.Column(db.Integer, db.ForeignKey('media.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Relationships
    media = db.relationship('Media', back_populates='descriptors')
    
    # Add an index on the key for faster lookups
    __table_args__ = (db.Index('idx_descriptor_key', 'key'),)
    
    def __repr__(self):
        return f'<Descriptor {self.key}: {self.value}>'

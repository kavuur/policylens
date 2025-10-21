from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

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
    password_hash = db.Column(db.String(128), nullable=True)  # Will store hashed passwords
    is_active = db.Column(db.Boolean(), default=True)
    age_group = db.Column(db.String(20), nullable=True)
    sex = db.Column(db.String(20), nullable=True)
    industry = db.Column(db.String(100), nullable=True)
    organization = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    
    # Relationships
    codebooks = db.relationship('Codebook', back_populates='user', cascade='all, delete-orphan')
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

class PolicyDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='policies')

class Codebook(db.Model):
    __tablename__ = 'codebook'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', ondelete='CASCADE'), nullable=True)
    
    # Relationships
    user = db.relationship('User', back_populates='codebooks')
    project = db.relationship('Project', back_populates='codebooks')
    codes = db.relationship('Code', back_populates='codebook', cascade='all, delete-orphan')

class Code(db.Model):
    __tablename__ = 'code'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    codebook_id = db.Column(db.Integer, db.ForeignKey('codebook.id', ondelete='CASCADE'), nullable=False)
    
    # Relationships
    codebook = db.relationship('Codebook', back_populates='codes')
    subcodes = db.relationship('SubCode', back_populates='code', cascade='all, delete-orphan')

class SubCode(db.Model):
    __tablename__ = 'subcode'
    id = db.Column(db.Integer, primary_key=True)
    subcode = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    code_id = db.Column(db.Integer, db.ForeignKey('code.id', ondelete='CASCADE'), nullable=False)
    
    # Relationships
    code = db.relationship('Code', back_populates='subcodes')
    subsubcodes = db.relationship('SubSubCode', back_populates='subcode', cascade='all, delete-orphan')

class SubSubCode(db.Model):
    __tablename__ = 'subsubcode'
    id = db.Column(db.Integer, primary_key=True)
    subsubcode = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    subcode_id = db.Column(db.Integer, db.ForeignKey('subcode.id', ondelete='CASCADE'), nullable=False)
    
    # Relationships
    subcode = db.relationship('SubCode', back_populates='subsubcodes')

class ResearchNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='research_notes')



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
    filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    type = db.Column(db.String(50), nullable=False, default='other')
    visibility = db.Column(db.String(20), nullable=False, default='private')
    file_type = db.Column(db.String(50))  # e.g., 'image', 'document', 'video'
    file_size = db.Column(db.BigInteger)  # Store file size in bytes
    uploaded_at = db.Column(db.DateTime, server_default=db.func.now())
    
    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='media_items')
    
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', ondelete='CASCADE'), nullable=True)
    project = db.relationship('Project', back_populates='media_items')
    
    # One-to-many relationship with descriptors
    descriptors = db.relationship('Descriptor', backref='media', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Media {self.filename}>'


class Excerpt(db.Model):
    __tablename__ = 'excerpts'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', ondelete='CASCADE'), nullable=False)
    media_id = db.Column(db.Integer, db.ForeignKey('media.id', ondelete='CASCADE'), nullable=False)
    codebook_id = db.Column(db.Integer, db.ForeignKey('codebook.id', ondelete='CASCADE'), nullable=True)
    code = db.Column(db.String(100), nullable=True)
    subcode = db.Column(db.String(100), nullable=True)
    excerpt = db.Column(db.Text, nullable=False)
    explanation = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    project = db.relationship('Project', backref=db.backref('excerpts', lazy=True))
    media = db.relationship('Media', backref=db.backref('excerpts', lazy=True))
    codebook = db.relationship('Codebook', backref=db.backref('excerpts', lazy=True))
    user = db.relationship('User', backref=db.backref('excerpts', lazy=True))
    
    def __repr__(self):
        return f'<Excerpt {self.id} - {self.excerpt[:50]}...>'

class Descriptor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), nullable=False)  # e.g., 'year', 'author', 'location'
    value = db.Column(db.Text, nullable=False)       # e.g., '2020', 'John Doe', 'New York'
    
    # Foreign key to Media
    media_id = db.Column(db.Integer, db.ForeignKey('media.id', ondelete='CASCADE'), nullable=False)
    
    # Add an index on the key for faster lookups
    __table_args__ = (db.Index('idx_descriptor_key', 'key'),)
    
    def __repr__(self):
        return f'<Descriptor {self.key}: {self.value}>'

class User < ActiveRecord::Base
  attr_accessor :password
  before_save :encrypt_password
  
  validates_confirmation_of :password  
  validates_presence_of :email, :on => :create    
  validates_presence_of :password, :on => :create  
  
  validates_format_of :email, :with => /\A[^@]+@([^@\.]+\.)+[^@\.]+\z/
  validates_uniqueness_of :email
  has_many :photos
    
  def encrypt_password
    if password.present?
      self.password_salt = BCrypt::Engine.generate_salt
      self.password_hash = BCrypt::Engine.hash_secret(password, password_salt)
    end
  end
  
  def self.authenticate(login_name, password)
    users = self.where("email =?", login_name)
        
    if users
      user = users.first      
      if user && user.password_hash == BCrypt::Engine.hash_secret(password, user.password_salt)
        user
      else
        nil
      end
    end    
  end
    
  def to_json(options={})
    options[:except] ||= [:id, :password_hash, :password_salt, :email_verification, :verification_code, :created_at, :updated_at]
    super(options)
  end    
end
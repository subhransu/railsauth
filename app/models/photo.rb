class Photo < ActiveRecord::Base
  attr_accessor :name
  
  belongs_to :user
  
  def to_json(options={})
    options[:except] ||= [:id, :user_id, :created_at, :updated_at]
    super(options)
  end  
end

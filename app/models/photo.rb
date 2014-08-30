class Photo < ActiveRecord::Base
  attr_accessor :name, :title, :user_id, :image_url, :random_id
  
  belongs_to :user
  
  def to_json(options={})
    options[:except] ||= [:id, :user_id, :created_at, :updated_at]
    super(options)
  end  
end

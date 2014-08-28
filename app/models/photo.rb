class Photo < ActiveRecord::Base
  belongs_to :user
  
  def to_json(options={})
    options[:except] ||= [:id, :user_id, :created_at, :updated_at]
    super(options)
  end  
end

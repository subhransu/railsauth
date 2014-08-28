class Error 
  include ActiveModel::Validations
  include ActiveModel::Conversion
  extend ActiveModel::Naming
  
  attr_accessor :status, :message
  
  validates_presence_of :status
  validates_presence_of :message
  
  def initialize(attributes = {})
    attributes.each do |name, value|
      if name.eql?(:status)
        self.status = value
      elsif name.eql?(:message)        
        self.message = value
      end
    end
    self.to_json
  end
  
end

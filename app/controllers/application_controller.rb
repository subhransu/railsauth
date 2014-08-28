class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  
  def page_not_found
    e = Error.new(:status => 404, :message => "Wrong URL or HTTP method")    
    render :json => e.to_json, :status => 404
  end
end

class ApiController < ApplicationController  
  before_action :signup_key_verification, :only => [:signup, :signin, :get_token]
  
  def signup
    if request.post?
      if params && params[:full_name] && params[:email] && params[:password]
        
        params[:user] = Hash.new    
        params[:user][:first_name] = params[:full_name].split(" ").first
        params[:user][:last_name] = params[:full_name].split(" ").last
        params[:user][:email] = params[:email]
        params[:user][:password] = params[:password]    
        params[:user][:verification_code] = rand_string(20)

        @user = User.new(user_params)

        if @user.save
          render :json => @user.to_json, :status => 200
        else
          error_str = ""

          @user.errors.each{|attr, msg|           
            error_str += "#{attr} - #{msg},"
          }
                    
          e = Error.new(:status => 400, :message => error_str)
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end

  def signin
    if params && params[:email] && params[:password]      
      user = User.where(:email => params[:email]).first
      
      if user         
        if User.authenticate(params[:email], params[:password])            
          if !user.authtoken_expiry || user.authtoken_expiry < Time.now
            auth_token = rand_string(20)
            auth_expiry = Time.now + (24*60*60)
          
            user.update_attributes(:api_authtoken => auth_token, :authtoken_expiry => auth_expiry)          
          end 
            
          render :json => user.to_json, :status => 200
        else
          e = Error.new(:status => 401, :message => "Wrong Password")
          render :json => e.to_json, :status => 401
        end
      else
        e = Error.new(:status => 400, :message => "No user record found for this email ID")
        render :json => e.to_json, :status => 400
      end
    else
      e = Error.new(:status => 400, :message => "required parameters are missing")
      render :json => e.to_json, :status => 400
    end
  end
  
  def reset_password
    if params && params[:authtoken] && params[:email] && params[:old_password] && params[:new_password]   
      user = User.where(:email => params[:email]).first
      
      if user         
        if user.api_authtoken == params[:authtoken] && user.authtoken_expiry > Time.now
          if User.authenticate(params[:email], params[:old_password])  
            auth_token = rand_string(20)
            auth_expiry = Time.now + (24*60*60)
                      
            user.update_attributes(:password => params[:new_password], :api_authtoken => auth_token, :authtoken_expiry => auth_expiry)
            render :json => user.to_json, :status => 200
            
            # m = Message.new(:status => 200, :message => "Password is being reset!")
            # render :json => m.to_json, :status => 200            
          else
            e = Error.new(:status => 401, :message => "Wrong Password")
            render :json => e.to_json, :status => 401
          end
        else
          e = Error.new(:status => 401, :message => "Authtoken is invalid or has expired. Kindly refresh the token and try again!")
          render :json => e.to_json, :status => 401
        end
      else
        e = Error.new(:status => 400, :message => "No user record found for this email ID")
        render :json => e.to_json, :status => 400
      end
    else
      e = Error.new(:status => 400, :message => "required parameters are missing")
      render :json => e.to_json, :status => 400
    end
  end
  
  def get_token
    if params && params[:email]    
      user = User.where(:email => params[:email]).first
    
      if user 
        if !user.authtoken_expiry || user.authtoken_expiry < Time.now
          auth_token = rand_string(20)
          auth_expiry = Time.now + (24*60*60)
          
          user.update_attributes(:api_authtoken => auth_token, :authtoken_expiry => auth_expiry)          
        end        
        
        render :json => user.to_json(:only => [:api_authtoken, :authtoken_expiry])                
      else
        e = Error.new(:status => 400, :message => "No user record found for this email ID")
        render :json => e.to_json, :status => 400
      end
      
    else
      e = Error.new(:status => 400, :message => "required parameters are missing")
      render :json => e.to_json, :status => 400
    end
  end

  def clear_token
    if params && params[:authtoken] && params[:email]    
      user = User.where(:email => params[:email]).first
      
      if user         
        if user.api_authtoken == params[:authtoken] && user.authtoken_expiry > Time.now
          user.update_attributes(:api_authtoken => nil, :authtoken_expiry => nil)
          
          m = Message.new(:status => 200, :message => "Token is being cleared!")          
          render :json => m.to_json, :status => 200  
        else
          e = Error.new(:status => 401, :message => "Authtoken is invalid or has expired. Kindly refresh the token and try again!")
          render :json => e.to_json, :status => 401
        end
      else
        e = Error.new(:status => 400, :message => "No user record found for this email ID")
        render :json => e.to_json, :status => 400
      end
    else
      e = Error.new(:status => 400, :message => "required parameters are missing")
      render :json => e.to_json, :status => 400
    end
  end
  
  def upload_photo
    if request.post?
      if params[:authtoken] && params[:title] && params[:image]
        user = User.where(:api_authtoken => params[:authtoken]).first
          
        if user && user.authtoken_expiry > Time.now
          if user.photos.count < 3
            rand_id = rand_string(20)
            image_name = params[:image].original_filename
            image = MiniMagick::Image.read(params[:image].read)          
          
            img_public_path = "/public/uploads/#{rand_id}.png"
            image_local_file_path = File.join(Rails.root, img_public_path)
            image.write(image_local_file_path)
          
            photo = Photo.new(:name => image_name, :user_id => user.id, :title => params[:title], :image_url => "/uploads/#{rand_id}.png", :random_id => rand_id)
          
            if photo.save
              render :json => photo.to_json
            else
              error_str = ""

              @user.errors.each{|attr, msg|           
                error_str += "#{attr} - #{msg},"
              }
                    
              e = Error.new(:status => 400, :message => error_str)
              render :json => e.to_json, :status => 400
            end
          else
            e = Error.new(:status => 403, :message => "You have already uploaded 3 photos!")
            render :json => e.to_json, :status => 403
          end
        else
          e = Error.new(:status => 401, :message => "Authtoken is invalid or has expired. Kindly refresh the token and try again!")
          render :json => e.to_json, :status => 401
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end

  def delete_photo
    if request.post?
      if params[:authtoken] && params[:photo_id]
        user = User.where(:api_authtoken => params[:authtoken]).first
          
        if user && user.authtoken_expiry > Time.now
          photo = Photo.where(:random_id => params[:photo_id]).first
          
          if photo && photo.user_id == user.id            
            img_public_path = "/public#{photo.image_url}"
            image_local_file_path = File.join(Rails.root, img_public_path)
            
            File.delete(image_local_file_path) if File.exist?(image_local_file_path)
            photo.destroy
            
            m = Message.new(:status => 200, :message => "Image is deleted.")          
            render :json => m.to_json, :status => 200  
          else
            e = Error.new(:status => 401, :message => "You don't have permission to delete this photo!")
            render :json => e.to_json, :status => 401
          end
        else
          e = Error.new(:status => 401, :message => "Authtoken is invalid or has expired. Kindly refresh the token and try again!")
          render :json => e.to_json, :status => 401
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end

  def get_photos
    if params[:authtoken]
      user = User.where(:api_authtoken => params[:authtoken]).first
        
      if user && user.authtoken_expiry > Time.now
        photos = user.photos
        render :json => photos.to_json, :status => 200          
      else
        e = Error.new(:status => 401, :message => "Authtoken is invalid or has expired. Kindly refresh the token and try again!")
        render :json => e.to_json, :status => 401
      end
    else
      e = Error.new(:status => 400, :message => "required parameters are missing")
      render :json => e.to_json, :status => 400
    end
  end

  private 
  
  def signup_key_verification
    if !(params[:api_key] == "tUklCPqBvhubzzYoaXKzEKLJgWHFNVcNijJuqlxCP" && 
      params[:api_secret] == "VbxtrVWXefFBUGcOaCLNNpkLneXaqiNfJbLYrBIjc")
      
      e = Error.new(:status => 401, :message => "API credentials are missing or invalid")
      render :json => e.to_json, :status => 401
    end
  end
  
  def rand_string(len)
    o =  [('a'..'z'),('A'..'Z')].map{|i| i.to_a}.flatten
    string  =  (0..len).map{ o[rand(o.length)]  }.join

    return string
  end

  def rand_num(len)
    o =  [('0'..'9')].map{|i| i.to_a}.flatten
    number  =  (0..len).map{ o[rand(o.length)]  }.join

    return number
  end
  
  def user_params
    params.require(:user).permit(:first_name, :last_name, :email, :password, :password_hash, :password_salt, :verification_code, 
    :email_verification, :api_authtoken, :authtoken_expiry)
  end
  
  def photo_params
    params.require(:user).permit(:name, :title, :user_id, :image_url, :random_id)
  end
end
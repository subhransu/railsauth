class ApiController < ApplicationController  
  http_basic_authenticate_with name:ENV["API_AUTH_NAME"], password:name:ENV["API_AUTH_PASSWORD"], :only => [:signup, :signin, :get_token]  
  before_filter :check_for_valid_authtoken, :except => [:signup, :signin, :get_token]
  
  def signup
    if request.post?
      if params && params[:full_name] && params[:email] && params[:password]
        
        params[:user] = Hash.new    
        params[:user][:first_name] = params[:full_name].split(" ").first
        params[:user][:last_name] = params[:full_name].split(" ").last
        params[:user][:email] = params[:email]
        params[:passsword] = AESCrypt.decrypt(params[:passsword], ENV["API_AUTH_PASSWORD"])
        params[:user][:password] = params[:password]    
        params[:user][:verification_code] = rand_string(20)
        
        user = User.new(user_params)

        if user.save
          render :json => user.to_json, :status => 200
        else
          error_str = ""

          user.errors.each{|attr, msg|           
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
        e = Error.new(:status => 400, :message => "No USER found by this email ID")
        render :json => e.to_json, :status => 400
      end
    else
      e = Error.new(:status => 400, :message => "required parameters are missing")
      render :json => e.to_json, :status => 400
    end
  end
  
  def reset_password
    if params && params[:email] && params[:old_password] && params[:new_password]   
      user = User.where(:email => params[:email]).first
      
      if user         
        if user.authtoken_expiry > Time.now
          if User.authenticate(params[:email], params[:old_password])  
            
            auth_token = rand_string(20)
            auth_expiry = Time.now + (24*60*60)
            new_password = AESCrypt.decrypt(params[:new_password], ENV["API_AUTH_PASSWORD"])  
                      
            user.update_attributes(:password => new_password, :api_authtoken => auth_token, :authtoken_expiry => auth_expiry)
            render :json => user.to_json, :status => 200           
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
          
          m = Message.new(:status => 200, :message => "Token cleared")          
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
          rand_id = rand_string(40)
          image_name = params[:image].original_filename
          image = params[:image].read     
                    
          s3 = AWS::S3.new
            
          if s3
            bucket = s3.buckets[ENV["S3_BUCKET_NAME"]]
              
            if !bucket
              bucket = s3.buckets.create(ENV["S3_BUCKET_NAME"])
            end
              
            s3_obj = bucket.objects[rand_id]
            s3_obj.write(image, :acl => :public_read)
            image_url = s3_obj.public_url.to_s
                                                    
            photo = Photo.new(:name => image_name, :user_id => user.id, :title => params[:title], :image_url => image_url, :random_id => rand_id)
          
            if photo.save
              render :json => photo.to_json
            else
              error_str = ""

              photo.errors.each{|attr, msg|           
                error_str += "#{attr} - #{msg},"
              }
                    
              e = Error.new(:status => 400, :message => error_str)
              render :json => e.to_json, :status => 400
            end
          else
            e = Error.new(:status => 401, :message => "AWS S3 signature is wrong")
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

  def delete_photo
    if request.post?
      if params[:authtoken] && params[:photo_id]
        user = User.where(:api_authtoken => params[:authtoken]).first
          
        if user && user.authtoken_expiry > Time.now
          photo = Photo.where(:random_id => params[:photo_id]).first
          
          if photo && photo.user_id == user.id            
            s3 = AWS::S3.new
            
            if s3
              bucket = s3.buckets[ENV["S3_BUCKET_NAME"]]
              s3_obj =  bucket.objects[photo.random_id]
              s3_obj.delete
                            
              photo.destroy
            
              m = Message.new(:status => 200, :message => "Image deleted")          
              render :json => m.to_json, :status => 200  
            else
              e = Error.new(:status => 401, :message => "AWS S3 signature is wrong")
              render :json => e.to_json, :status => 401        
            end                        
          else
            e = Error.new(:status => 401, :message => "Invalid Photo ID or You don't have permission to delete this photo!")
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
  
  def check_for_valid_authtoken
    authenticate_or_request_with_http_token do |token, options|
      @user = User.where(:api_authtoken => token).first      
    end
  end
  
  def rand_string(len)
    o =  [('a'..'z'),('A'..'Z')].map{|i| i.to_a}.flatten
    string  =  (0..len).map{ o[rand(o.length)]  }.join

    return string
  end
  
  def user_params
    params.require(:user).permit(:first_name, :last_name, :email, :password, :password_hash, :password_salt, :verification_code, 
    :email_verification, :api_authtoken, :authtoken_expiry)
  end
  
  def photo_params
    params.require(:photo).permit(:name, :title, :user_id, :random_id, :image_url)
  end
    
end
class AddRandomIdToPhotos < ActiveRecord::Migration
  def change
    add_column :photos, :random_id, :string    
  end
end

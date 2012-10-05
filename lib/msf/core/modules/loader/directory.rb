# Concerns loading module from a directory
class Msf::Modules::Loader::Directory < Msf::Modules::Loader::Base
  # Returns true if the path is a directory
  #
  # @param (see Msf::Modules::Loader::Base#loadable?)
  # @return [true] if path is a directory
  # @return [false] otherwise
  def loadable?(path)
    if File.directory?(path)
      true
    else
      false
    end
  end

  protected

  # Yields the module_reference_name for each module file found under the directory path.
  #
  # @param [String] path The path to the directory.
  # @yield (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @yieldparam [String] path The path to the directory.
  # @yieldparam [String] type The type correlated with the directory under path.
  # @yieldparam module_reference_name (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @return (see Msf::Modules::Loader::Base#each_module_reference_name)
  def each_module_reference_name(path)
    ::Dir.foreach(path) do |entry|
      if entry.downcase == '.svn'
        next
      end

      full_entry_path = ::File.join(path, entry)
      type = entry.singularize

      unless ::File.directory?(full_entry_path) and
             module_manager.type_enabled? type
        next
      end

      full_entry_pathname = Pathname.new(full_entry_path)

      # Try to load modules from all the files in the supplied path
      Rex::Find.find(full_entry_path) do |entry_descendant_path|
        if module_path?(entry_descendant_path)
          entry_descendant_pathname = Pathname.new(entry_descendant_path)
          relative_entry_descendant_pathname = entry_descendant_pathname.relative_path_from(full_entry_pathname)
          relative_entry_descendant_path = relative_entry_descendant_pathname.to_path

          # The module_reference_name doesn't have a file extension
          module_reference_name = module_reference_name_from_path(relative_entry_descendant_path)

          yield path, type, module_reference_name
        end
      end
    end
  end

  # Returns the full path to the module file on disk.
  #
  # @param (see Msf::Modules::Loader::Base#module_path)
  # @return [String] Path to module file on disk.
  def module_path(parent_path, type, module_reference_name)
    typed_path = self.typed_path(type, module_reference_name)
    full_path = File.join(parent_path, typed_path)

    full_path
  end

  # Loads the module content from the on disk file.
  #
  # @param (see Msf::Modules::Loader::Base#read_module_content)
  # @return (see Msf::Modules::Loader::Base#read_module_content)
  def read_module_content(parent_path, type, module_reference_name)
    full_path = module_path(parent_path, type, module_reference_name)

    ::File.read(full_path)
  end
end
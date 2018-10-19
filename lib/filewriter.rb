class FileWriter

  attr_reader :scanner, :basedir

  def initialize(scanner)
    @scanner = scanner
  end

  def directory
    time    = Time.now.strftime("%d%b%Y_%H%M%S")
    @basedir = "#{Dir.home}/Documents/Sherlock_Out/Sherlock_#{time}"
    FileUtils.mkdir_p(basedir) unless File.exists?(basedir)
  end

  def iterate_data
    scanner.buildchecks.each do |check|
      create_file(check)
    end
    puts "Evidence written to #{basedir}".cyan.bold
  end

  def create_file(check)
    unless check['out'].nil?
      out_file = File.new("#{basedir}/#{check['ip']}_#{check['port']}_#{check['name'].gsub(" ", "_")}_#{check['command']}.txt", "w") #this won't work now.
      out_file.puts(check['out'])
      out_file.close
    end
  end

end

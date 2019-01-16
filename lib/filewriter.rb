class FileWriter

  attr_reader :scanner

  def initialize(scanner, buildchecks)
    @scanner     = scanner
    @buildchecks = buildchecks
  end

  def iterate_data
    scanner.buildchecks.each do |check|
      create_file(check)
    end
    puts "Evidence written to #{@buildchecks.basedir}".cyan.bold
  end

  def create_file(check)
    unless check['out'].nil?
      out_file = File.new("#{@buildchecks.basedir}/#{check['ip']}_#{check['port']}_#{check['name'].gsub(" ", "_")}_#{check['command']}.txt", "w") #this won't work now.
      out_file.puts(check['out'])
      out_file.close
    end
  end

end

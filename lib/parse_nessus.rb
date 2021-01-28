class ParseNessus

  attr_reader :vuln_array, :nessus_files, :choices

  def initialize
    @nessus_files = Dir.glob(ARGV[0] + '/*.{nessus,xml}')
    @vuln_array = []
  end

  def choose_nessus_files
    prompt  = TTY::Prompt.new
    if nessus_files.length > 1
      @choices = prompt.multi_select("Which Nessus files would you like to use?", nessus_files, per_page: 20, echo: false)
    else
      @choices = @nessus_files
    end
  end

  def parse_nessus_file
    choices.each do |choice|
      puts "Parsing #{choice}...."
      nessus_file = Nokogiri::XML(File.read(choice))
      nessus_file.xpath('//NessusClientData_v2/Report/ReportHost').each do |host|
        vulns = {}
        vulns[:ip] = host.xpath('./@name').text

        host.xpath('./ReportItem').each do |item|
          vulns[:name]       = item.xpath('./@pluginName').text
          vulns[:proto]      = item.xpath('./@protocol').text
          vulns[:port]       = item.xpath('./@port').text
          vulns[:pluginid]   = item.xpath('./@pluginID').text
          vuln_array << vulns.dup
        end
      end
    end
    puts "Nessus File(s) Parsed....\n".green.bold
    vuln_array.uniq! { |h| h}
  end

end

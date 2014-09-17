require 'omniauth'
require 'ruby-saml'
require 'uuid'

module OmniAuth
  module Strategies
    class SAML
      include OmniAuth::Strategy

      option :name_identifier_format, nil
      option :idp_sso_target_url_runtime_params, {}

      def request_phase
        options[:assertion_consumer_service_url] ||= callback_url
        runtime_request_parameters = options.delete(:idp_sso_target_url_runtime_params)

        additional_params = {}
        runtime_request_parameters.each_pair do |request_param_key, mapped_param_key|
          additional_params[mapped_param_key] = request.params[request_param_key.to_s] if request.params.has_key?(request_param_key.to_s)
        end if runtime_request_parameters

        authn_request = OneLogin::RubySaml::Authrequest.new
        settings = OneLogin::RubySaml::Settings.new(options)
                
        uuid = UUID.new.generate
        additional_params[:uri] = "_" + uuid         
        params = authn_request.create_params(settings, additional_params)
        #OmniAuth.config.logger.debug(settings.idp_sso_target_url.inspect)
        #OmniAuth.config.logger.debug(params.inspect)
        #OmniAuth.config.logger.debug(Base64.decode64(params['SAMLRequest']))
        params['RelayState'] = uuid
        
        # TODO Support both redirect and POST
        # How to select method?
        #redirect(authn_request.create(settings, additional_params))
        post_request(settings.idp_sso_target_url, params)
      end
      
      def post_request(url, params)
        r = Rack::Response.new
        r.write("<html><body><form method=\"post\" id=\"samlform\" action=\"#{url}\">\n<input type=\"hidden\" name=\"SAMLRequest\" value=\"#{params['SAMLRequest']}\" /><input type=\"hidden\" name=\"RelayState\" value=\"#{params['RelayState']}\" /></form></body><script type=\"text/javascript\">document.getElementById('samlform').submit();</script></html>")
        r.finish
      end

      def callback_phase
        unless request.params['SAMLResponse']
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing")
        end

        response = OneLogin::RubySaml::Response.new(request.params['SAMLResponse'], options)
        response.settings = OneLogin::RubySaml::Settings.new(options)
        
        OmniAuth.logger.debug(response.inspect)

        @name_id = response.name_id
        @attributes = response.attributes

        if @name_id.nil? || @name_id.empty?
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing 'name_id'")
        end

        response.validate!

        super
      rescue OmniAuth::Strategies::SAML::ValidationError
        fail!(:invalid_ticket, $!)
      rescue OneLogin::RubySaml::ValidationError
        fail!(:invalid_ticket, $!)
      end

      def other_phase
        if on_path?("#{request_path}/metadata")
          # omniauth does not set the strategy on the other_phase
          @env['omniauth.strategy'] ||= self
          setup_phase

          response = OneLogin::RubySaml::Metadata.new
          settings = OneLogin::RubySaml::Settings.new(options)
          Rack::Response.new(response.generate(settings), 200, { "Content-Type" => "application/xml" }).finish
        else
          call_app!
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @attributes[:name],
          :email => @attributes[:email] || @attributes[:mail],
          :first_name => @attributes[:first_name] || @attributes[:firstname] || @attributes[:firstName],
          :last_name => @attributes[:last_name] || @attributes[:lastname] || @attributes[:lastName]
        }
      end

      extra { { :raw_info => @attributes } }
    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'

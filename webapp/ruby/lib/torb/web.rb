require 'json'
require 'sinatra/base'
require 'erubi'
require 'mysql2'
require 'mysql2-cs-bind'

module Torb
  class Web < Sinatra::Base
    configure :development do
      require 'sinatra/reloader'
      register Sinatra::Reloader
    end

    set :root, File.expand_path('../..', __dir__)
    set :sessions, key: 'torb_session', expire_after: 3600
    set :session_secret, 'tagomoris'
    set :protection, frame_options: :deny

    set :erb, escape_html: true

    set :login_required, ->(value) do
      condition do
        if value && !get_login_user
          halt_with_error 401, 'login_required'
        end
      end
    end

    set :admin_login_required, ->(value) do
      condition do
        if value && !get_login_administrator
          halt_with_error 401, 'admin_login_required'
        end
      end
    end

    before '/api/*|/admin/api/*' do
      content_type :json
    end

    helpers do
      def db
        Thread.current[:db] ||= Mysql2::Client.new(
          host: ENV['DB_HOST'],
          port: ENV['DB_PORT'],
          username: ENV['DB_USER'],
          password: ENV['DB_PASS'],
          database: ENV['DB_DATABASE'],
          database_timezone: :utc,
          cast_booleans: true,
          reconnect: true,
          init_command: 'SET SESSION sql_mode="STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"',
        )
      end

      def get_events(where = nil)
        where ||= ->(e) { e['public_fg'] }

        db.query('BEGIN')
        begin
          event_ids = db.query('SELECT * FROM events ORDER BY id ASC').select(&where).map { |e| e['id'] }
          events = event_ids.map do |event_id|
            event = get_event(event_id)
            event['sheets'].each { |sheet| sheet.delete('detail') }
            event
          end
          db.query('COMMIT')
        rescue
          db.query('ROLLBACK')
        end

        events
      end

      def get_events_list(where = nil)
        where ||= ->(e) { e['public_fg'] }

        db.query('BEGIN')
        begin
          sheets_ranks = db.query('SELECT rank,price,count(*) as count FROM sheets GROUP BY rank,price')

          events = db.query('SELECT * FROM events ORDER BY id ASC').select(&where).map do |event|
            event['total']   = 0
            event['remains'] = 0
            event['sheets'] = {}

            %w[S A B C].each do |rank|
              event['sheets'][rank] = { 'total' => 0, 'remains' => 0, 'detail' => [] }
              selected = sheets_ranks.select{ |sheets_rank| sheets_rank['rank'] == rank}.first
              event['sheets'][rank]['price'] ||= event['price'] + selected['price']
              event['total'] += selected['count']
              event['sheets'][rank]['total'] = selected['count']
            end

            event['remains'] = event['total']
            reserve_counts = db.xquery('SELECT rank,count(*) as count FROM reservations r inner join sheets s on r.sheet_id = s.id WHERE r.event_id = ? AND r.canceled_at IS NULL group by rank', event['id'])
            %w[S A B C].each do |rank|
              count = 0 
              selected = reserve_counts.select{|reserve_count| reserve_count['rank'] == rank}
              if selected.size > 0 then
                count = selected.first['count']
              end
              event['sheets'][rank]['remains'] = event['sheets'][rank]['total'] - count
              event['remains'] = event['remains'] - count
            end
            # event['remains'] = event['total'] - db.xquery('SELECT count(*) as count FROM reservations WHERE event_id = ? AND canceled_at IS NULL', event['id']).first['count']
            # %w[S A B C].each do |rank|
            #   event['sheets'][rank]['remains'] = event['sheets'][rank]['total'] - db.xquery('SELECT count(*) as count FROM reservations r inner join sheets s on r.sheet_id = s.id WHERE r.event_id = ? AND r.canceled_at IS NULL AND s.rank = ?', event['id'],rank).first['count']
            # end

            event['public'] = event.delete('public_fg')
            event['closed'] = event.delete('closed_fg')
            event
          end
          db.query('COMMIT')
        rescue
          db.query('ROLLBACK')
        end

        events
      end

      def get_event(event_id, login_user_id = nil)
        event = db.xquery('SELECT * FROM events WHERE id = ?', event_id).first
        return unless event

        # zero fill
        event['total']   = 0
        event['remains'] = 0
        event['sheets'] = {}
        %w[S A B C].each do |rank|
          event['sheets'][rank] = { 'total' => 0, 'remains' => 0, 'detail' => [] }
        end

        sheets = db.xquery('SELECT s.rank as rank,s.num as num ,s.price as price, r.reserved_at as reserved_at_date,r.user_id as reserve_user_id FROM sheets s left join reservations r on s.id = r.sheet_id and r.canceled_at is null and r.event_id = ? ORDER BY `rank`, num',event['id'])
        sheets.each do |sheet|
          event['sheets'][sheet['rank']]['price'] ||= event['price'] + sheet['price']
          event['total'] += 1
          event['sheets'][sheet['rank']]['total'] += 1

          if sheet['reserved_at_date']
            sheet['mine']        = true if login_user_id && sheet['reserve_user_id'] == login_user_id
            sheet['reserved']    = true
            sheet['reserved_at'] = sheet['reserved_at_date'].to_i
          else
            event['remains'] += 1
            event['sheets'][sheet['rank']]['remains'] += 1
          end

          event['sheets'][sheet['rank']]['detail'].push(sheet)
          sheet.delete('reserve_user_id')
          sheet.delete('reserved_at_date')
          sheet.delete('price')
          sheet.delete('rank')
        end

        event['public'] = event.delete('public_fg')
        event['closed'] = event.delete('closed_fg')

        event
      end

      def sanitize_event(event)
        sanitized = event.dup  # shallow clone
        sanitized.delete('price')
        sanitized.delete('public')
        sanitized.delete('closed')
        sanitized
      end

      def get_login_user
        user_id = session[:user_id]
        return unless user_id
        db.xquery('SELECT id, nickname FROM users WHERE id = ?', user_id).first
      end

      def get_login_administrator
        administrator_id = session['administrator_id']
        return unless administrator_id
        db.xquery('SELECT id, nickname FROM administrators WHERE id = ?', administrator_id).first
      end

      def validate_rank(rank)
        db.xquery('SELECT COUNT(*) AS total_sheets FROM sheets WHERE `rank` = ?', rank).first['total_sheets'] > 0
      end

      def body_params
        @body_params ||= JSON.parse(request.body.tap(&:rewind).read)
      end

      def halt_with_error(status = 500, error = 'unknown')
        halt status, { error: error }.to_json
      end

      def render_report_csv(reports)
        #reports = reports.sort_by { |report| report[:sold_at] }

        #header
        keys = %i[reservation_id event_id rank num price user_id sold_at canceled_at]
        body = keys.join(',')
        body << "\n"

        # body
        reports.each do |report|
          body << report['csv']
          body << "\n"
        end

        headers({
          'Content-Type'        => 'text/csv; charset=UTF-8',
          'Content-Disposition' => 'attachment; filename="report.csv"',
        })
        body
      end
    end

    get '/' do
      @user   = get_login_user
      @events = get_events_list.map(&method(:sanitize_event))
      erb :index
    end

    get '/initialize' do
      system "../../db/init.sh"

      status 204
    end

    post '/api/users' do
      nickname   = body_params['nickname']
      login_name = body_params['login_name']
      password   = body_params['password']

      db.query('BEGIN')
      begin
        duplicated = db.xquery('SELECT * FROM users WHERE login_name = ?', login_name).first
        if duplicated
          db.query('ROLLBACK')
          halt_with_error 409, 'duplicated'
        end

        db.xquery('INSERT INTO users (login_name, pass_hash, nickname) VALUES (?, SHA2(?, 256), ?)', login_name, password, nickname)
        user_id = db.last_id
        db.query('COMMIT')
      rescue => e
        warn "rollback by: #{e}"
        db.query('ROLLBACK')
        halt_with_error
      end

      status 201
      { id: user_id, nickname: nickname }.to_json
    end

    get '/api/users/:id', login_required: true do |user_id|
      user = db.xquery('SELECT id, nickname FROM users WHERE id = ?', user_id).first
      if user['id'] != get_login_user['id']
        halt_with_error 403, 'forbidden'
      end

      rows = db.xquery('SELECT r.*, s.rank AS sheet_rank, s.num AS sheet_num FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id WHERE r.user_id = ? ORDER BY IFNULL(r.canceled_at, r.reserved_at) DESC LIMIT 5', user['id'])
      recent_reservations = rows.map do |row|
        event = db.xquery('SELECT * FROM events WHERE id = ?', row['event_id']).first
        event['public'] = event.delete('public_fg')
        event['closed'] = event.delete('closed_fg')

        price = db.xquery(' select e.price + s.price as price from events e inner join sheets s on s.rank = ? where e.id = ? limit 1',row['sheet_rank'],row['event_id']).first['price']
        event.delete('sheets')
        event.delete('total')
        event.delete('remains')

        {
          id:          row['id'],
          event:       event,
          sheet_rank:  row['sheet_rank'],
          sheet_num:   row['sheet_num'],
          price:       price,
          reserved_at: row['reserved_at'].to_i,
          canceled_at: row['canceled_at']&.to_i,
        }
      end

      user['recent_reservations'] = recent_reservations
      user['total_price'] = db.xquery('SELECT IFNULL(SUM(e.price + s.price), 0) AS total_price FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id WHERE r.user_id = ? AND r.canceled_at IS NULL', user['id']).first['total_price']

      sheets = db.query('SELECT * FROM sheets ORDER BY `rank`, num')

      rows = db.xquery('SELECT event_id FROM reservations WHERE user_id = ? GROUP BY event_id ORDER BY MAX(IFNULL(canceled_at, reserved_at)) DESC LIMIT 5', user['id'])
      recent_events = rows.map do |row|
        event = db.xquery('SELECT * FROM events WHERE id = ?', row['event_id']).first
        # zero fill
        event['total']   = 0
        event['remains'] = 0
        event['sheets'] = {}
        %w[S A B C].each do |rank|
          event['sheets'][rank] = { 'total' => 0, 'remains' => 0 }
        end

        sheets.each do |sheet|
          event['sheets'][sheet['rank']]['price'] ||= event['price'] + sheet['price']
          event['total'] += 1
          event['sheets'][sheet['rank']]['total'] += 1
        end

        event['remains'] = event['total']
        reserve_counts = db.xquery('SELECT rank,count(*) as count FROM reservations r inner join sheets s on r.sheet_id = s.id WHERE r.event_id = ? AND r.canceled_at IS NULL group by rank', event['id'])
        %w[S A B C].each do |rank|
          count = 0 
          selected = reserve_counts.select{|reserve_count| reserve_count['rank'] == rank}
          if selected.size > 0 then
            count = selected.first['count']
          end
          event['sheets'][rank]['remains'] = event['sheets'][rank]['total'] - count
          event['remains'] = event['remains'] - count
        end
        event['public'] = event.delete('public_fg')
        event['closed'] = event.delete('closed_fg')
        event
      end
      user['recent_events'] = recent_events

      user.to_json
    end


    post '/api/actions/login' do
      login_name = body_params['login_name']
      password   = body_params['password']

      user      = db.xquery('SELECT * FROM users WHERE login_name = ?', login_name).first
      pass_hash = db.xquery('SELECT SHA2(?, 256) AS pass_hash', password).first['pass_hash']
      halt_with_error 401, 'authentication_failed' if user.nil? || pass_hash != user['pass_hash']

      session['user_id'] = user['id']

      user = get_login_user
      user.to_json
    end

    post '/api/actions/logout', login_required: true do
      session.delete('user_id')
      status 204
    end

    get '/api/events' do
      events = get_events.map(&method(:sanitize_event))
      events.to_json
    end

    get '/api/events/:id' do |event_id|
      user = get_login_user || {}
      event = get_event(event_id, user['id'])
      halt_with_error 404, 'not_found' if event.nil? || !event['public']

      event = sanitize_event(event)
      event.to_json
    end

    post '/api/events/:id/actions/reserve', login_required: true do |event_id|
      rank = body_params['sheet_rank']

      user  = get_login_user
      event = get_event(event_id, user['id'])
      halt_with_error 404, 'invalid_event' unless event && event['public']
      halt_with_error 400, 'invalid_rank' unless validate_rank(rank)

      sheet = nil
      reservation_id = nil
      loop do
        sheet = db.xquery('SELECT * FROM sheets WHERE id NOT IN (SELECT sheet_id FROM reservations WHERE event_id = ? AND canceled_at IS NULL FOR UPDATE) AND `rank` = ? ORDER BY RAND() LIMIT 1', event['id'], rank).first
        halt_with_error 409, 'sold_out' unless sheet
        db.query('BEGIN')
        begin
          db.xquery('INSERT INTO reservations (event_id, sheet_id, user_id, reserved_at) VALUES (?, ?, ?, ?)', event['id'], sheet['id'], user['id'], Time.now.utc.strftime('%F %T.%6N'))
          reservation_id = db.last_id
          db.query('COMMIT')
        rescue => e
          db.query('ROLLBACK')
          warn "re-try: rollback by #{e}"
          next
        end

        break
      end

      status 202
      { id: reservation_id, sheet_rank: rank, sheet_num: sheet['num'] } .to_json
    end

    delete '/api/events/:id/sheets/:rank/:num/reservation', login_required: true do |event_id, rank, num|
      user  = get_login_user
      event = get_event(event_id, user['id'])
      halt_with_error 404, 'invalid_event' unless event && event['public']
      halt_with_error 404, 'invalid_rank'  unless validate_rank(rank)

      sheet = db.xquery('SELECT * FROM sheets WHERE `rank` = ? AND num = ?', rank, num).first
      halt_with_error 404, 'invalid_sheet' unless sheet

      db.query('BEGIN')
      begin
        reservation = db.xquery('SELECT * FROM reservations WHERE event_id = ? AND sheet_id = ? AND canceled_at IS NULL GROUP BY event_id HAVING reserved_at = MIN(reserved_at) FOR UPDATE', event['id'], sheet['id']).first
        unless reservation
          db.query('ROLLBACK')
          halt_with_error 400, 'not_reserved'
        end
        if reservation['user_id'] != user['id']
          db.query('ROLLBACK')
          halt_with_error 403, 'not_permitted'
        end

        db.xquery('UPDATE reservations SET canceled_at = ? WHERE id = ?', Time.now.utc.strftime('%F %T.%6N'), reservation['id'])
        db.query('COMMIT')
      rescue => e
        warn "rollback by: #{e}"
        db.query('ROLLBACK')
        halt_with_error
      end

      status 204
    end

    get '/admin/' do
      @administrator = get_login_administrator
      @events = get_events_list(->(_) { true }) if @administrator

      erb :admin
    end

    post '/admin/api/actions/login' do
      login_name = body_params['login_name']
      password   = body_params['password']

      administrator = db.xquery('SELECT * FROM administrators WHERE login_name = ?', login_name).first
      pass_hash     = db.xquery('SELECT SHA2(?, 256) AS pass_hash', password).first['pass_hash']
      halt_with_error 401, 'authentication_failed' if administrator.nil? || pass_hash != administrator['pass_hash']

      session['administrator_id'] = administrator['id']

      administrator = get_login_administrator
      administrator.to_json
    end

    post '/admin/api/actions/logout', admin_login_required: true do
      session.delete('administrator_id')
      status 204
    end

    get '/admin/api/events', admin_login_required: true do
      events = get_events(->(_) { true })
      events.to_json
    end

    post '/admin/api/events', admin_login_required: true do
      title  = body_params['title']
      public = body_params['public'] || false
      price  = body_params['price']

      db.query('BEGIN')
      begin
        db.xquery('INSERT INTO events (title, public_fg, closed_fg, price) VALUES (?, ?, 0, ?)', title, public, price)
        event_id = db.last_id
        db.query('COMMIT')
      rescue
        db.query('ROLLBACK')
      end

      event = get_event(event_id)
      event&.to_json
    end

    get '/admin/api/events/:id', admin_login_required: true do |event_id|
      event = get_event(event_id)
      halt_with_error 404, 'not_found' unless event

      event.to_json
    end

    post '/admin/api/events/:id/actions/edit', admin_login_required: true do |event_id|
      public = body_params['public'] || false
      closed = body_params['closed'] || false
      public = false if closed

      event = get_event(event_id)
      halt_with_error 404, 'not_found' unless event

      if event['closed']
        halt_with_error 400, 'cannot_edit_closed_event'
      elsif event['public'] && closed
        halt_with_error 400, 'cannot_close_public_event'
      end

      db.query('BEGIN')
      begin
        db.xquery('UPDATE events SET public_fg = ?, closed_fg = ? WHERE id = ?', public, closed, event['id'])
        db.query('COMMIT')
      rescue
        db.query('ROLLBACK')
      end

      event = get_event(event_id)
      event.to_json
    end

    get '/admin/api/reports/events/:id/sales', admin_login_required: true do |event_id|
      event = get_event(event_id)

      reports = db.xquery('SELECT CONCAT(r.id,",",e.id,",", s.rank,",",s.num,",",e.price+s.price,",",r.user_id,",", DATE_FORMAT(r.reserved_at, "%Y-%m-%dT%TZ") , ",",case r.canceled_at is null when 1 then "" else DATE_FORMAT(r.canceled_at, "%Y-%m-%dT%TZ") end) as csv  FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id WHERE r.event_id = ? ORDER BY reserved_at ASC FOR UPDATE', event['id'])

      render_report_csv(reports)
    end

    get '/admin/api/reports/sales', admin_login_required: true do
      #reservations = db.query('SELECT STRAIGHT_JOIN r.id as reservation_id,e.id AS event_id, s.rank AS rank, s.num AS num,r.user_id as user_id, DATE_FORMAT(r.reserved_at, "%Y-%m-%dT%TZ") as sold_at , case r.canceled_at is null when 1 then "" else DATE_FORMAT(r.canceled_at, "%Y-%m-%dT%TZ") end as canceled_at ,e.price+s.price AS price FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id ORDER BY reserved_at ASC FOR UPDATE')
      reports = db.query('SELECT STRAIGHT_JOIN CONCAT(r.id,",",e.id,",", s.rank,",",s.num,",",e.price+s.price,",",r.user_id,",", DATE_FORMAT(r.reserved_at, "%Y-%m-%dT%TZ") , ",",case r.canceled_at is null when 1 then "" else DATE_FORMAT(r.canceled_at, "%Y-%m-%dT%TZ") end) as csv FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id ORDER BY reserved_at ASC FOR UPDATE')
      render_report_csv(reports)
    end
  end
end

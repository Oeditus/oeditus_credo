defmodule OeditusCredo.Crap.ScoreTest do
  use ExUnit.Case, async: true

  alias OeditusCredo.Crap.Score

  describe "score/2" do
    test "returns complexity unchanged for 100 percent coverage" do
      assert Score.score(7, 100) == {:ok, 7.0}
    end

    test "returns complexity squared plus complexity for 0 percent coverage" do
      assert Score.score(4, 0) == {:ok, 20.0}
    end

    test "preserves fractional scores for intermediate coverage" do
      assert Score.score(4, 75) == {:ok, 4.25}
    end

    test "rejects invalid complexity" do
      assert Score.score(-1, 50) == {:error, :invalid_complexity}
      assert Score.score(:high, 50) == {:error, :invalid_complexity}
    end

    test "rejects invalid coverage" do
      assert Score.score(4, -1) == {:error, :invalid_coverage}
      assert Score.score(4, 101) == {:error, :invalid_coverage}
      assert Score.score(4, :covered) == {:error, :invalid_coverage}
    end

    test "rejects fractional coverage outside the valid range" do
      assert Score.score(4, -0.1) == {:error, :invalid_coverage}
      assert Score.score(4, 100.1) == {:error, :invalid_coverage}
    end
  end
end
